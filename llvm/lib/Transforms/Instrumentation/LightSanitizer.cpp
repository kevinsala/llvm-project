//===-- LightSanitizer.cpp - Light Sanitizer --------------------------===//
//
// Part of the LLVM Project, under the Apache License v2.0 with LLVM Exceptions.
// See https://llvm.org/LICENSE.txt for license information.
// SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception
//
//===----------------------------------------------------------------------===//
//
//===----------------------------------------------------------------------===//

#include "llvm/Transforms/Instrumentation/LightSanitizer.h"

#include "llvm/ADT/PostOrderIterator.h"
#include "llvm/ADT/STLExtras.h"
#include "llvm/ADT/SetVector.h"
#include "llvm/ADT/SmallVector.h"
#include "llvm/Analysis/PostDominators.h"
#include "llvm/Analysis/ValueTracking.h"
#include "llvm/Frontend/OpenMP/OMP.h"
#include "llvm/IR/Argument.h"
#include "llvm/IR/BasicBlock.h"
#include "llvm/IR/Constants.h"
#include "llvm/IR/DebugInfoMetadata.h"
#include "llvm/IR/DerivedTypes.h"
#include "llvm/IR/Dominators.h"
#include "llvm/IR/GlobalValue.h"
#include "llvm/IR/GlobalVariable.h"
#include "llvm/IR/IRBuilder.h"
#include "llvm/IR/InstIterator.h"
#include "llvm/IR/Instruction.h"
#include "llvm/IR/Instructions.h"
#include "llvm/IR/IntrinsicInst.h"
#include "llvm/IR/Intrinsics.h"
#include "llvm/IR/IntrinsicsAMDGPU.h"
#include "llvm/IR/LLVMContext.h"
#include "llvm/IR/Module.h"
#include "llvm/IR/NoFolder.h"
#include "llvm/IR/ReplaceConstant.h"
#include "llvm/IR/Value.h"
#include "llvm/IR/Verifier.h"
#include "llvm/Support/Casting.h"
#include "llvm/Support/ErrorHandling.h"
#include "llvm/Transforms/Utils/BasicBlockUtils.h"
#include "llvm/Transforms/Utils/Cloning.h"
#include "llvm/Transforms/Utils/ModuleUtils.h"
#include "llvm/Transforms/Utils/ValueMapper.h"
#include <cstdint>
#include <string>

using namespace llvm;

#define DEBUG_TYPE "light-sanitizer"

enum {
  GlobalAS = 1,
  SharedAS = 3,
  ConstantAS = 4,
};

static constexpr StringRef ShadowGlobalPrefix = "__lightsan_global.";
static constexpr StringRef ShadowSharedPrefix = "__lightsan_shared.";
static constexpr StringRef ShadowConstantPrefix = "__lightsan_constant.";
static constexpr StringRef GlobalIgnorePrefix[] = {"llvm."};
static constexpr StringRef GlobalIgnoreParts[] = {"__lightsan_", "__san"};
static constexpr StringRef SafeAnnotation = "__lightsan_safe";

static bool canInstrumentGlobal(const GlobalVariable &G) {
  auto Name = G.getName();
  if (Name.empty())
    return false;
  for (const auto &S : GlobalIgnorePrefix)
    if (Name.starts_with(S))
      return false;
  for (const auto &S : GlobalIgnoreParts)
    if (Name.contains(S))
      return false;
  return any_of(G.uses(),
                [](const Use &U) { return isa<Instruction>(U.getUser()); });
}

static Twine getShadowGlobalName(const GlobalValue &G) {
  return ShadowGlobalPrefix + G.getName();
}

namespace llvm {

struct LocationInfoTy {
  uint64_t LineNo = 0;
  uint64_t ColumnNo = 0;
  uint64_t ParentIdx = -1;
  StringRef FileName;
  StringRef FunctionName;
  bool operator==(const LocationInfoTy &RHS) const {
    return LineNo == RHS.LineNo && ColumnNo == RHS.ColumnNo &&
           FileName == RHS.FileName && FunctionName == RHS.FunctionName;
  }
};
template <> struct DenseMapInfo<LocationInfoTy *> {
  static LocationInfoTy EmptyKey;
  static LocationInfoTy TombstoneKey;
  static inline LocationInfoTy *getEmptyKey() { return &EmptyKey; }

  static inline LocationInfoTy *getTombstoneKey() { return &TombstoneKey; }

  static unsigned getHashValue(const LocationInfoTy *LI) {
    unsigned Hash = DenseMapInfo<uint64_t>::getHashValue(LI->LineNo);
    Hash = detail::combineHashValue(
        Hash, DenseMapInfo<uint64_t>::getHashValue(LI->ColumnNo));
    Hash = detail::combineHashValue(
        Hash, DenseMapInfo<StringRef>::getHashValue(LI->FileName));
    Hash = detail::combineHashValue(
        Hash, DenseMapInfo<StringRef>::getHashValue(LI->FunctionName));
    return Hash;
  }

  static bool isEqual(const LocationInfoTy *LHS, const LocationInfoTy *RHS) {
    return *LHS == *RHS;
  }
};
LocationInfoTy DenseMapInfo<LocationInfoTy *>::EmptyKey =
    LocationInfoTy{(uint64_t)-1};
LocationInfoTy DenseMapInfo<LocationInfoTy *>::TombstoneKey =
    LocationInfoTy{(uint64_t)-2};
} // namespace llvm

namespace {

class LightSanitizerImpl final {
public:
  LightSanitizerImpl(Module &M, FunctionAnalysisManager &FAM)
      : M(M), FAM(FAM), Ctx(M.getContext()) {
    if (auto *Fn = M.getFunction("__lightsan_get_as0_info"))
      InfoTy = Fn->getReturnType();
  }

  bool instrument();

private:
  /// We support address space 0 to 5 right now.
  static constexpr int NumSupportedAddressSpaces = 6;

  bool isASType(Type &T) {
    return T.isPointerTy() && T.getPointerAddressSpace();
  };
  Type *getWithoutAS(Type &T) {
    return isASType(T) ? PointerType::get(T.getContext(), 0) : &T;
  };

  bool shouldInstrumentFunction(Function *Fn);

  struct AccessInfoTy {
    Instruction *I;
    unsigned PtrOpIdx;
    unsigned AS;
    enum { READ = 1, WRITE = 2, ATOMIC = 4 };
    uint32_t Kind;
    bool Checked = false;

    uint32_t encodeKindInSize(uint32_t Size) { return Size | (Kind << 29); }
  };

  struct PtrInfoTy {
    Value *Start;
    Value *Length;
    Value *AS;
    AllocaInst *Alloca;
  };
  DenseMap<Value *, PtrInfoTy> AllocationInfoMap;
  StringMap<Value *> GlobalStringMap;

  DenseMap<LocationInfoTy *, uint64_t, DenseMapInfo<LocationInfoTy *>>
      LocationMap;

  const std::pair<LocationInfoTy *, uint64_t>
  addLocationInfo(LocationInfoTy *LI, bool &IsNew) {
    auto It = LocationMap.insert({LI, LocationMap.size()});
    IsNew = It.second;
    if (!IsNew)
      delete LI;
    return {It.first->first, It.first->second};
  }

  uint64_t addString(StringRef S) {
    const auto &It = UniqueStrings.insert({S, ConcatenatedString.size()});
    if (It.second) {
      ConcatenatedString += S;
      ConcatenatedString.push_back('\0');
    }
    return It.first->second;
  };

  void encodeLocationInfo(LocationInfoTy &LI, uint64_t Idx) {
    StringRef FunctionName = LI.FunctionName;
#if 0
    auto PN = omp::prettifyFunctionName(FunctionName);
    FunctionName = SS.save(PN);
#endif

    auto FuncIdx = addString(FunctionName);
    auto FileIdx = addString(LI.FileName);
    if (LocationEncoding.size() < (Idx + 1) * 5)
      LocationEncoding.resize((Idx + 1) * 5);
    LocationEncoding[Idx * 5 + 0] = ConstantInt::get(Int64Ty, FuncIdx);
    LocationEncoding[Idx * 5 + 1] = ConstantInt::get(Int64Ty, FileIdx);
    LocationEncoding[Idx * 5 + 2] = ConstantInt::get(Int64Ty, LI.LineNo);
    LocationEncoding[Idx * 5 + 3] = ConstantInt::get(Int64Ty, LI.ColumnNo);
    LocationEncoding[Idx * 5 + 4] = ConstantInt::get(Int64Ty, LI.ParentIdx);
  }

  ConstantInt *getSourceIndex(Instruction &I,
                              LocationInfoTy *LastLI = nullptr) {
    LocationInfoTy *LI = new LocationInfoTy();
    auto *DILoc = I.getDebugLoc().get();

    auto FillLI = [&](LocationInfoTy &LI, DILocation &DIL) {
      LI.FileName = DIL.getFilename();
      if (LI.FileName.empty())
        LI.FileName = I.getFunction()->getSubprogram()->getFilename();
      LI.FunctionName = DIL.getSubprogramLinkageName();
      if (LI.FunctionName.empty())
        LI.FunctionName = I.getFunction()->getName();
      LI.LineNo = DIL.getLine();
      LI.ColumnNo = DIL.getColumn();
    };

    DILocation *ParentDILoc = nullptr;
    if (DILoc) {
      FillLI(*LI, *DILoc);
      ParentDILoc = DILoc->getInlinedAt();
    } else {
      LI->FunctionName = I.getFunction()->getName();
    }

    bool IsNew;
    uint64_t Idx;
    std::tie(LI, Idx) = addLocationInfo(LI, IsNew);
    if (LastLI)
      LastLI->ParentIdx = Idx;
    if (!IsNew)
      return ConstantInt::get(Int64Ty, Idx);

    uint64_t CurIdx = Idx;
    LocationInfoTy *CurLI = LI;
    while (ParentDILoc) {
      auto *ParentLI = new LocationInfoTy();
      FillLI(*ParentLI, *ParentDILoc);
      uint64_t ParentIdx;
      std::tie(ParentLI, ParentIdx) = addLocationInfo(ParentLI, IsNew);
      CurLI->ParentIdx = ParentIdx;
      if (!IsNew)
        break;
      encodeLocationInfo(*CurLI, CurIdx);
      CurLI = ParentLI;
      CurIdx = ParentIdx;
      ParentDILoc = ParentDILoc->getInlinedAt();
    }

    Function &Fn = *I.getFunction();
    buildCallTreeInfo(Fn, *CurLI);

    encodeLocationInfo(*CurLI, CurIdx);

    return ConstantInt::get(Int64Ty, Idx);
  }

  ConstantInt *getSourceIndex(const GlobalVariable *G) {
    SmallVector<DIGlobalVariableExpression *, 1> GlobalLocations;
    G->getDebugInfo(GlobalLocations);

    LocationInfoTy *LI = new LocationInfoTy();
    if (GlobalLocations.empty()) {
      LI->FunctionName = G->getName();
    } else {
      const auto *DLVar = GlobalLocations.front()->getVariable();
      LI->FileName = DLVar->getFilename();
      LI->LineNo = DLVar->getLine();
      LI->FunctionName = DLVar->getName();
      LI->ColumnNo = 0;
    }

    bool IsNew;
    uint64_t Idx;
    std::tie(LI, Idx) = addLocationInfo(LI, IsNew);
    //errs() << "GV GV " << *G << " :: " << IsNew << " : " << Idx << "\n";

    if (IsNew)
      encodeLocationInfo(*LI, Idx);

    return ConstantInt::get(Int64Ty, Idx);
  }

  void buildCallTreeInfo(Function &Fn, LocationInfoTy &LI) {
    if (Fn.hasFnAttribute("kernel"))
      return;
    SmallVector<CallBase *> Calls;
    for (auto &U : Fn.uses()) {
      auto *CB = dyn_cast<CallBase>(U.getUser());
      if (!CB)
        continue;
      if (!CB->isCallee(&U))
        continue;
      Calls.push_back(CB);
    }
    if (Calls.size() == 1) {
      getSourceIndex(*Calls.back(), &LI);
      return;
    }
    LI.ParentIdx = -2;
    AmbiguousCalls.insert(Calls.begin(), Calls.end());
  }

  SmallVector<Constant *> LocationEncoding;
  std::string ConcatenatedString;
  DenseMap<uint64_t, uint64_t> StringIndexMap;
  DenseMap<StringRef, uint64_t> UniqueStrings;

  SmallVector<Function *> Kernels;
  GlobalVariable *LocationsArray = nullptr;
  SmallSetVector<CallBase *, 16> AmbiguousCalls;
  int AllocationId = 1;

  BumpPtrAllocator BPA;
  StringSaver SS = StringSaver(BPA);

  bool handleAmbiguousCalls();
#if 0
  bool handleCallStackSupport();
  bool finalizeKernels();
#endif

  bool addCtor();
  bool addDtor();

#if 0
  Function *createSanitizerInitKernel();
#endif

  Value *getFunctionName(IRBuilder<NoFolder> &IRB);
  Value *getFileName(IRBuilder<NoFolder> &IRB);
  Value *getLineNo(IRBuilder<NoFolder> &IRB);

  PtrInfoTy getPtrInfoTy(Value &Obj, const AccessInfoTy &AI, Instruction &BaseIP) {
    if (AI.AS > 1)
      return {
          PoisonValue::get(InfoTy->getContainedType(0)->getContainedType(0)),
          PoisonValue::get(InfoTy->getContainedType(0)->getContainedType(1)),
          PoisonValue::get(InfoTy->getContainedType(1))};
    PtrInfoTy &AllocationInfo = AllocationInfoMap[&Obj];
    if (!AllocationInfo.Start) {
      Instruction *IP;
      if (auto *PHI = dyn_cast<PHINode>(&Obj)) {
        IP = PHI->getParent()->getFirstNonPHIOrDbgOrLifetime();
      } else if (auto *I = dyn_cast<Instruction>(&Obj)) {
        IP = I->getNextNode();
      } else if (isa<Argument>(Obj)) {
#if 0
        IP = &*cast<Argument>(Obj)
                   .getParent()
                   ->getEntryBlock()
                   .getFirstNonPHIOrDbgOrAlloca();
#endif
        IP = &BaseIP;
      } else {
#if 0
        IP = &*AI.I->getFunction()
                   ->getEntryBlock()
                   .getFirstNonPHIOrDbgOrAlloca();
#endif
        IP = &BaseIP;
      }

      IRBuilder<NoFolder> IRB(IP);
      auto *AllocaStruct = IRB.CreateAlloca(InfoTy);
      createCall(IRB, getGetAllocationInfoFn(AI.AS),
                 {getPC(IRB), getSourceIndex(*AI.I),
                 IRB.CreateAddrSpaceCast(&Obj, PtrTy),
                 AllocaStruct});
      auto *LoadStruct = IRB.CreateLoad(InfoTy, AllocaStruct);
      AllocationInfo = PtrInfoTy{
          IRB.CreateExtractValue(LoadStruct, {0, 0}, "obj.base"),
          IRB.CreateExtractValue(LoadStruct, {0, 1}, "obj.size"),
          IRB.CreateExtractValue(LoadStruct, {1}, "obj.as"),
          AllocaStruct};
    }
    return AllocationInfo;
  }

#if 0
  void removeAS(Function &Fn, SmallVectorImpl<Instruction *> &ASInsts);
#endif

  bool instrumentFunction(Function &Fn, SmallVectorImpl<CallInst *> &CallInsts);
  bool instrumentMainFunction();
  void instrumentTrapInsts(SmallVectorImpl<IntrinsicInst *> &TrapInsts);
  void instrumentUnreachableInsts(
      SmallVectorImpl<UnreachableInst *> &UnreachableInsts);

  void instrumentGlobal(IRBuilder<NoFolder> &IRB, GlobalVariable &GV,
                        uint32_t AS);
  void instrumentCallInsts(SmallVectorImpl<CallInst *> &CallInsts);
  void instrumentLifetimeIntrinsics(
      SmallVectorImpl<LifetimeIntrinsic *> &LifetimeInsts);
  void instrumentAccesses(DominatorTree &DT, PostDominatorTree &PDT,
                          SmallVectorImpl<AccessInfoTy> &Accesses);
  void instrumentAllocaInstructions(SmallVectorImpl<AllocaInst *> &AllocaInsts);

  bool hasSafeAnnotation(Instruction *I) {
    if (!I->hasMetadata(LLVMContext::MD_annotation))
      return false;

    return any_of(I->getMetadata(LLVMContext::MD_annotation)->operands(),
                 [&](const MDOperand &Op) {
                   StringRef AnnotationStr =
                       isa<MDString>(Op.get())
                           ? cast<MDString>(Op.get())->getString()
                           : cast<MDString>(
                                 cast<MDTuple>(Op.get())->getOperand(0).get())
                                 ->getString();
                   return (AnnotationStr == SafeAnnotation);
                 });
  }

  bool isSafeCallArg(Value *Op) {
    if (!Op->getType()->isPointerTy())
      return true;
    if (Op == ConstantPointerNull::get(PtrTy))
      return true;
    // Avoid sanitizing external global variables for the moment
    if (auto *LI = dyn_cast<LoadInst>(Op))
      if (auto *GEP = dyn_cast<GetElementPtrInst>(LI->getPointerOperand()))
        if (auto *GV = dyn_cast<GlobalVariable>(GEP->getPointerOperand()))
          return GV->hasExternalLinkage();
    return false;
  }

  FunctionCallee getOrCreateFn(FunctionCallee &FC, StringRef Name, Type *RetTy,
                               ArrayRef<Type *> ArgTys) {
    if (!FC) {
      auto *NewAllocationFnTy = FunctionType::get(RetTy, ArgTys, false);
      FC = M.getOrInsertFunction(Name, NewAllocationFnTy);
    }
    return FC;
  }

  /// int32_t ompx_global_thread_id();
  FunctionCallee ThreadIDFn;
  FunctionCallee getThreadIdFn() {
    return getOrCreateFn(ThreadIDFn, "ompx_global_thread_id", Int32Ty, {});
  }

  /// void ompx_sync_block_acq_rel();
  FunctionCallee SyncBlockFn;
  FunctionCallee getSyncBlockFn() {
    return getOrCreateFn(SyncBlockFn, "ompx_sync_block_acq_rel", VoidTy, {});
  }

  /// void __lightsan_leak_check();
  FunctionCallee getLeakCheckFn() {
    FunctionCallee LeakCheckFn;
    return getOrCreateFn(LeakCheckFn, "__lightsan_leak_check", VoidTy, {});
  }

  /// void __lightsan_trap_info(Int64Ty);
  FunctionCallee TrapInfoFn;
  FunctionCallee getTrapInfoFn() {
    return getOrCreateFn(TrapInfoFn, "__lightsan_trap_info", VoidTy,
                         {/*PC*/ Int64Ty, /*LocationId*/ Int64Ty});
  }

  /// void __lightsan_unreachable_info(Int64Ty);
  FunctionCallee UnreachableInfoFn;
  FunctionCallee getUnreachableInfoFn() {
    return getOrCreateFn(UnreachableInfoFn, "__lightsan_unreachable_info",
                         VoidTy, {/*PC*/ Int64Ty, /*LocationId*/ Int64Ty});
  }

  /// PtrTy __lightsan_unpack(Int64Ty, PtrTy);
  FunctionCallee UnpackFns[NumSupportedAddressSpaces];
  FunctionCallee getUnpackFn(uint32_t AS) {
    assert(AS < NumSupportedAddressSpaces && "Unexpected address space!");
    return getOrCreateFn(
        UnpackFns[AS], "__lightsan_unpack_as" + std::to_string(AS),
        ASPtrTy[AS], {/*PC*/ Int64Ty, /*LocationId*/ Int64Ty, PtrTy});
  }

  /// InfoTy __lightsan_get_as<AS>_info(Int64Ty, Int64Ty, PtrTy);
  FunctionCallee GetAllocationInfoFn[NumSupportedAddressSpaces];
  FunctionCallee getGetAllocationInfoFn(unsigned AS) {
    assert(AS < NumSupportedAddressSpaces && "Unexpected address space!");
    return getOrCreateFn(GetAllocationInfoFn[AS],
                         "__lightsan_get_as" + std::to_string(AS) + "_info",
                         VoidTy, {Int64Ty, Int64Ty, PtrTy, PtrTy});
  }

  /// ptr(0) __lightsan_check_as0_access_with_info(/* PC */Int64Ty,
  /// 						     /*LocationId*/ Int64Ty,
  /// 					             /* FakePtr */ PtrTy,
  /// 				                     /* Size */Int32Ty,
  /// 				                     /* AS */Int32Ty,
  /// 				                     /* PI.Base */ ptr(1),
  /// 				                     /* PI.Size */ Int64Ty);
  /// ptr(AS) __lightsan_check_as<AS>_access_with_info(/* PC */Int64Ty,
  /// 					                  /* FakePtr */ PtrTy,
  /// 				                          /* Size */Int32Ty,
  /// 				                          /* AS */Int32Ty,
  /// 				                          /* PI.Base */ ptr(1),
  /// 				                          /* PI.Size */
  /// Int64Ty);
  FunctionCallee CheckAccessWithInfoFn[NumSupportedAddressSpaces];
  FunctionCallee getCheckAccessWithInfoFn(unsigned AS) {
    assert(AS < NumSupportedAddressSpaces && "Unexpected address space!");
    return getOrCreateFn(CheckAccessWithInfoFn[AS],
                         "__lightsan_check_as" + std::to_string(AS) +
                             "_access_with_info",
                         ASPtrTy[AS],
                         {/*PC*/ Int64Ty, /*LocationId*/ Int64Ty, PtrTy,
                          Int32Ty, Int32Ty, Int32Ty, Int32Ty});
  }

  /// PtrTy __lightsan_register_alloca(/* PC */ Int64Ty, /*LocationId*/
  /// Int64Ty,
  /// 						/* RealPtr */ AllocaPtrTy,
  /// 						/* Size */ Int32Ty);
  FunctionCallee AllocaRegisterFn;
  FunctionCallee getAllocaRegisterFn() {
    getOrCreateFn(
        AllocaRegisterFn, "__lightsan_register_alloca", PtrTy,
        {/*PC*/ Int64Ty, /*LocationId*/ Int64Ty, AllocaPtrTy, Int32Ty});
    //    cast<Function>(AllocaRegisterFn.getCallee())
    //        ->addRetAttr(Attribute::NoAlias);
    return AllocaRegisterFn;
  }

  /// PtrTy __lightsan_global(/* PC */ Int64Ty, /*LocationId*/ Int64Ty,
  /// 						/* RealPtr */ ASPtrTy[AS],
  /// 						/* Size */ Int64Ty);
  FunctionCallee GlobalRegisterFn[NumSupportedAddressSpaces];
  FunctionCallee getGlobalRegisterFn(uint32_t AS) {
    assert(AS < NumSupportedAddressSpaces && "Unexpected address space!");
    getOrCreateFn(
        GlobalRegisterFn[AS],
        "__lightsan_register_as" + std::to_string(AS) + "_global", PtrTy,
        {/*PC*/ Int64Ty, /*LocationId*/ Int64Ty, ASPtrTy[AS], Int64Ty});
    return GlobalRegisterFn[AS];
  }

  FunctionCallee MainArgsRegisterFn;
  FunctionCallee getMainArgsRegisterFn() {
    getOrCreateFn(
        MainArgsRegisterFn,
        "__lightsan_register_main_args", PtrTy,
        {/*PC*/ Int64Ty, /*LocationId*/ Int64Ty, Int32Ty, PtrTy});
    return MainArgsRegisterFn;
  }

  CallInst *createCall(IRBuilder<NoFolder> &IRB, FunctionCallee Callee,
                       ArrayRef<Value *> Args = std::nullopt,
                       const Twine &Name = "") {
    RTCalls.push_back(IRB.CreateCall(Callee, Args, Name));
    return RTCalls.back();
  }
  SmallVector<CallInst *> RTCalls;

  Value *getPC(IRBuilder<NoFolder> &IRB) {
    static int X = 0;
    return ConstantInt::get(Int64Ty, X++);
    return IRB.CreateIntrinsic(Int64Ty, Intrinsic::amdgcn_s_getpc, {}, nullptr,
                               "PC");
  }

  Module &M;
  const DataLayout &DL = M.getDataLayout();
  FunctionAnalysisManager &FAM;
  LLVMContext &Ctx;

  Type *VoidTy = Type::getVoidTy(Ctx);
  Type *IntptrTy = M.getDataLayout().getIntPtrType(Ctx);
  PointerType *PtrTy = PointerType::getUnqual(Ctx);
  IntegerType *Int8Ty = Type::getInt8Ty(Ctx);
  IntegerType *Int32Ty = Type::getInt32Ty(Ctx);
  IntegerType *Int64Ty = Type::getInt64Ty(Ctx);
  PointerType *AllocaPtrTy = PointerType::get(Ctx, DL.getAllocaAddrSpace());
  PointerType *GlobalPtrTy = PointerType::get(Ctx, 1);
  PointerType *ASPtrTy[NumSupportedAddressSpaces] = {
      PointerType::get(Ctx, 0), PointerType::get(Ctx, 1),
      PointerType::get(Ctx, 2), PointerType::get(Ctx, 3),
      PointerType::get(Ctx, 4), PointerType::get(Ctx, 5)};
  Type *AllocationInfoTy = StructType::create(Ctx, {Int32Ty, Int32Ty}, "PtrInfoTy", true);
  Type *InfoTy = StructType::create(Ctx, {AllocationInfoTy, Int32Ty}, "PtrASInfoTy", true);
};

} // end anonymous namespace

bool LightSanitizerImpl::shouldInstrumentFunction(Function *Fn) {
  if (!Fn || Fn->isDeclaration())
    return false;
  return !Fn->hasFnAttribute(Attribute::DisableSanitizerInstrumentation);
}

#if 0
void LightSanitizerImpl::removeAS(Function &Fn,
                                    SmallVectorImpl<Instruction *> &ASInsts) {

  DenseMap<Value *, Value *> VMap;

  std::function<Value *(Value &)> GetAsGeneric = [&](Value &V) -> Value * {
    if (!isASType(*V.getType()))
      return &V;
    auto *&NewV = VMap[&V];
    if (!NewV) {
      auto *IP = &Fn.getEntryBlock().front();
      if (auto *PHI = dyn_cast<PHINode>(&V))
        IP = PHI->getParent()->getFirstNonPHIOrDbgOrLifetime();
      else if (auto *I = dyn_cast<Instruction>(&V))
        IP = I->getNextNode();
      NewV = new AddrSpaceCastInst(&V, getWithoutAS(*V.getType()),
                                   V.getName() + ".noas", IP);
    }
    return NewV;
  };

  SmallVector<PHINode *> PHIs;
  for (auto *I : ASInsts) {
    //errs() << "I: " << *I << "\n";
    switch (I->getOpcode()) {
    case Instruction::Load: {
      auto &LI = cast<LoadInst>(*I);
      auto *GenericOp = GetAsGeneric(*LI.getPointerOperand());
      if (LI.getPointerAddressSpace())
        GenericOp = new AddrSpaceCastInst(GenericOp, LI.getPointerOperandType(),
                                          GenericOp->getName() + ".as", &LI);
      LI.setOperand(LI.getPointerOperandIndex(), GenericOp);
      VMap[I] = GetAsGeneric(LI);
      break;
    }
    case Instruction::Store: {
      auto &SI = cast<StoreInst>(*I);
      auto *GenericOp = GetAsGeneric(*SI.getPointerOperand());
      if (SI.getPointerAddressSpace())
        GenericOp = new AddrSpaceCastInst(GenericOp, SI.getPointerOperandType(),
                                          GenericOp->getName() + ".as", &SI);
      SI.setOperand(SI.getPointerOperandIndex(), GenericOp);
      break;
    }
    case Instruction::AtomicRMW: {
      auto &ARMW = cast<AtomicRMWInst>(*I);
      auto *GenericOp = GetAsGeneric(*ARMW.getPointerOperand());
      if (ARMW.getPointerAddressSpace())
        GenericOp = new AddrSpaceCastInst(GenericOp,
                                          ARMW.getPointerOperand()->getType(),
                                          GenericOp->getName() + ".as", &ARMW);
      ARMW.setOperand(ARMW.getPointerOperandIndex(), GenericOp);
      VMap[I] = GetAsGeneric(ARMW);
      break;
    }
    case Instruction::AtomicCmpXchg: {
      auto &ACX = cast<AtomicCmpXchgInst>(*I);
      auto *GenericOp = GetAsGeneric(*ACX.getPointerOperand());
      if (ACX.getPointerAddressSpace())
        GenericOp =
            new AddrSpaceCastInst(GenericOp, ACX.getPointerOperand()->getType(),
                                  GenericOp->getName() + ".as", &ACX);
      ACX.setOperand(ACX.getPointerOperandIndex(), GenericOp);
      VMap[I] = GetAsGeneric(ACX);
      break;
    }
    case Instruction::GetElementPtr: {
      auto &GEP = cast<GetElementPtrInst>(*I);
      GEP.mutateType(getWithoutAS(*GEP.getType()));
      GEP.setSourceElementType(getWithoutAS(*GEP.getSourceElementType()));
      GEP.setResultElementType(getWithoutAS(*GEP.getResultElementType()));
      GEP.setOperand(GEP.getPointerOperandIndex(),
                     GetAsGeneric(*GEP.getPointerOperand()));
      break;
    }
    case Instruction::AddrSpaceCast: {
      auto &ASC = cast<AddrSpaceCastInst>(*I);
      Value *PlainV;
      VMap[I] = PlainV = GetAsGeneric(*ASC.getPointerOperand());
      while (!ASC.use_empty()) {
        Use &U = *ASC.use_begin();
        U.set(PlainV);
      }
      ASC.eraseFromParent();
      break;
    }
    case Instruction::Select: {
      auto &SI = cast<SelectInst>(*I);
      SI.mutateType(getWithoutAS(*SI.getType()));
      SI.setTrueValue(GetAsGeneric(*SI.getTrueValue()));
      SI.setFalseValue(GetAsGeneric(*SI.getFalseValue()));
      break;
    }
    case Instruction::PHI: {
      auto &PHI = cast<PHINode>(*I);
      PHI.mutateType(getWithoutAS(*PHI.getType()));
      PHIs.push_back(&PHI);
      break;
    }
    case Instruction::ICmp: {
      auto &II = cast<ICmpInst>(*I);
      II.setOperand(0, GetAsGeneric(*II.getOperand(0)));
      II.setOperand(1, GetAsGeneric(*II.getOperand(1)));
      break;
    }
    case Instruction::Call: {
      auto &CI = cast<CallInst>(*I);
      auto *Callee = CI.getCalledFunction();
      if (shouldInstrumentFunction(Callee)) {
        for (unsigned I = 0, E = CI.arg_size(); I < E; ++I)
          CI.setArgOperand(I, GetAsGeneric(*CI.getArgOperand(I)));

        auto *FT = CI.getFunctionType();
        SmallVector<Type *> ArgTypes;
        for (auto *ArgType : FT->params())
          ArgTypes.push_back(getWithoutAS(*ArgType));
        FunctionType *NewFT = FunctionType::get(
            getWithoutAS(*FT->getReturnType()), ArgTypes, FT->isVarArg());
        CI.mutateFunctionType(NewFT);
        CI.mutateType(getWithoutAS(*CI.getType()));
      } else {
        if (isASType(*CI.getType()))
          VMap[I] = GetAsGeneric(CI);
        IRBuilder<NoFolder> IRB(&CI);
        for (unsigned I = 0, E = CI.arg_size(); I < E; ++I) {
          auto *Op = CI.getArgOperand(I);
          if (!isASType(*Op->getType()))
            continue;
          auto *NewOp = GetAsGeneric(*Op);
          Value *NewArg = IRB.CreateAddrSpaceCast(NewOp, Op->getType());
          CI.setArgOperand(I, NewArg);
        }
      }
      break;
    }
    default:
      //I->dump();
      llvm_unreachable("Instruction with AS not handled");
    }
    //  if (VMap.count(I))
    //    errs() << "I: " << *I << " --> " << *VMap[I] << "\n";
  }

  for (auto *PHI : PHIs)
    for (unsigned I = 0, E = PHI->getNumIncomingValues(); I < E; ++I)
      PHI->setIncomingValue(I, GetAsGeneric(*PHI->getIncomingValue(I)));
}
#endif

void LightSanitizerImpl::instrumentCallInsts(
    SmallVectorImpl<CallInst *> &CallInsts) {
  for (auto *CI : CallInsts) {
    assert(!isa<LifetimeIntrinsic>(CI));
    auto *Fn = CI->getCalledFunction();
    if (shouldInstrumentFunction(Fn))
      continue;
    IRBuilder<NoFolder> IRB(CI);
    for (int I = 0, E = CI->arg_size(); I != E; ++I) {
      Value *Op = CI->getArgOperand(I);
      if (isSafeCallArg(Op))
        continue;

      auto *PlainOp = Op;
      auto AS = Op->getType()->getPointerAddressSpace();
      if (AS)
        if (auto *AC = dyn_cast<AddrSpaceCastInst>(Op))
          PlainOp = AC->getPointerOperand();
      auto *CB = createCall(IRB, getUnpackFn(AS),
                            {getPC(IRB), getSourceIndex(*CI),
                             IRB.CreateAddrSpaceCast(PlainOp, PtrTy)},
                            Op->getName() + ".unpack");
      //CB->dump();
      CI->setArgOperand(I, CB);
    }
  }
}

void LightSanitizerImpl::instrumentLifetimeIntrinsics(
    SmallVectorImpl<LifetimeIntrinsic *> &LifetimeInsts) {
  for (auto *LI : LifetimeInsts)
    LI->eraseFromParent();
}

void LightSanitizerImpl::instrumentTrapInsts(
    SmallVectorImpl<IntrinsicInst *> &TrapInsts) {
  for (auto *II : TrapInsts) {
    IRBuilder<NoFolder> IRB(II);
    createCall(IRB, getTrapInfoFn(), {getPC(IRB), getSourceIndex(*II)});
  }
}

void LightSanitizerImpl::instrumentUnreachableInsts(
    SmallVectorImpl<UnreachableInst *> &UnreachableInsts) {
  for (auto *II : UnreachableInsts) {
    // Skip unreachables after traps since we instrument those as well.
    if (&II->getParent()->front() != II)
      if (auto *CI = dyn_cast<CallInst>(II->getPrevNode()))
        if (CI->getIntrinsicID() == Intrinsic::trap)
          continue;
    IRBuilder<NoFolder> IRB(II);
    createCall(IRB, getUnreachableInfoFn(), {getPC(IRB), getSourceIndex(*II)});
  }
}

void LightSanitizerImpl::instrumentAccesses(
    DominatorTree &DT, PostDominatorTree &PDT,
    SmallVectorImpl<AccessInfoTy> &AccessInfos) {
  DenseMap<Value *, SmallVector<Instruction *>> CheckedPtrs;
  DenseMap<std::pair<BasicBlock *, Value *>,
           SmallVector<std::pair<AccessInfoTy *, APInt>>>
      BlockMap;

  auto CheckAccess = [&](AccessInfoTy &AI, Value *Ptr, Instruction *IP,
                         APInt &Offset) {
    auto AccessSize = DL.getTypeStoreSize(AI.I->getAccessType());
    Offset -= AccessSize;
    auto *Size = ConstantInt::get(Int32Ty, AI.encodeKindInSize(AccessSize));

    auto *Obj = getUnderlyingObject(Ptr);
    if (AI.AS == 0)
      AI.AS = Obj->getType()->getPointerAddressSpace();
    if (AI.AS == 0 && isa<Argument>(Obj))
      if (cast<Argument>(Obj)->getParent()->getCallingConv() ==
          CallingConv::AMDGPU_KERNEL)
        AI.AS = 1;

    //    if (AI.AS == 1)
    //      AI.AS = 0;

    Instruction *BaseIP = IP->getParent()->getFirstNonPHIOrDbgOrLifetime();

    const auto &PtrInfo = getPtrInfoTy(*Obj, AI, *BaseIP);

    if (auto *PtrI = dyn_cast<Instruction>(Ptr))
      if (DT.dominates(PtrI, IP) && PDT.dominates(IP, PtrI))
        IP = PtrI->getNextNode();
    if (Obj == Ptr && isa<Instruction>(PtrInfo.AS))
      IP = cast<Instruction>(PtrInfo.AS)->getNextNode();

    IRBuilder<NoFolder> IRB(IP);
    Ptr = IRB.CreateAddrSpaceCast(Ptr, PtrTy);
    Ptr = IRB.CreateGEP(Int8Ty, Ptr,
                        {ConstantInt::get(Int32Ty, Offset.getSExtValue())});
    SmallVector<Value *> Args;
    Args.append({getPC(IRB), getSourceIndex(*AI.I), Ptr, Size});

    Args.push_back(PtrInfo.AS);
    Args.push_back(PtrInfo.Start);
    Args.push_back(PtrInfo.Length);
    auto *RealPtr = createCall(IRB, getCheckAccessWithInfoFn(AI.AS), Args);
    AI.I->setOperand(AI.PtrOpIdx, RealPtr);

    assert(RealPtr->getParent());
    auto *FakePtr = AI.I->getOperand(AI.PtrOpIdx);
    CheckedPtrs[FakePtr].push_back(RealPtr);
    return RealPtr;
  };

  auto MovePtrOps = [&](Instruction *IP, Value *Ptr) {
    auto *PtrI = dyn_cast<Instruction>(Ptr);
    if (!PtrI || IP == Ptr)
      return true;
    SmallVector<Instruction *> Worklist;
    SmallVector<Instruction *> Visited;
    Worklist.push_back(PtrI);
    while (!Worklist.empty()) {
      auto *I = Worklist.pop_back_val();
      if (DT.dominates(I, IP))
        continue;
      Visited.push_back(I);
      if (I->mayHaveSideEffects() || I->mayReadFromMemory())
        return false;
      for (auto &Op : I->operands()) {
        if (auto *OpI = dyn_cast<Instruction>(&Op))
          Worklist.push_back(OpI);
      }
    }
    sort(Visited, [&](const Instruction *LHS, const Instruction *RHS) {
      return DT.dominates(LHS, RHS);
    });
    for (auto *I : Visited)
      I->moveBefore(IP);
    return true;
  };

  for (auto &AI : AccessInfos) {
    auto *FakePtr = AI.I->getOperand(AI.PtrOpIdx);
    if (FakePtr->getType()->getPointerAddressSpace()) {
      auto *ASC = cast<AddrSpaceCastInst>(FakePtr);
      FakePtr = ASC->getPointerOperand();
    }
    AI.AS = FakePtr->getType()->getPointerAddressSpace();
    APInt Offset(DL.getIndexSizeInBits(AI.AS), 0);

    Value *SafePtr = nullptr;
    auto *StrippedPtr =
        FakePtr->stripAndAccumulateConstantOffsets(DL, Offset, true);
    APInt OffsetAndSize = Offset + DL.getTypeStoreSize(AI.I->getAccessType());
    if (auto *GV = dyn_cast<GlobalVariable>(StrippedPtr)) {
      if (APInt(OffsetAndSize.getBitWidth(),
                DL.getTypeStoreSize(GV->getValueType()))
              .uge(OffsetAndSize)) {
        SafePtr = GV;
      }
    } else if (auto *AllocI = dyn_cast<AllocaInst>(StrippedPtr)) {
      if (APInt(OffsetAndSize.getBitWidth(),
                DL.getTypeStoreSize(AllocI->getAllocatedType()))
              .uge(OffsetAndSize)) {
		// if store type size >= offset+storesize
        SafePtr = AllocI;
      }
    }
    if (SafePtr) {
      IRBuilder<NoFolder> IRB(AI.I);
      auto *Ptr = cast<Instruction>(IRB.CreateGEP(
          Int8Ty, SafePtr, {ConstantInt::get(Int32Ty, Offset.getSExtValue())}));
      Ptr->addAnnotationMetadata(SafeAnnotation);
      Value *ASPtr = IRB.CreateAddrSpaceCast(
          Ptr, AI.I->getOperand(AI.PtrOpIdx)->getType());
      AI.I->setOperand(AI.PtrOpIdx, ASPtr);
      AI.Checked = true;
      continue;
    }

    BlockMap[{AI.I->getParent(), StrippedPtr}].push_back({&AI, OffsetAndSize});
  }

  for (auto &It : BlockMap) {
    if (It.second.size() < 2)
      continue;
    //errs() << "IT.second size " << It.second.size() << "\n";
    sort(It.second, [&](const std::pair<const AccessInfoTy *, APInt> &LHS,
                        const std::pair<const AccessInfoTy *, APInt> &RHS) {
      return DT.dominates(LHS.first->I, RHS.first->I);
    });
    //errs() << "IT.second size " << It.second.size() << "\n";
    Instruction *IP = It.second.front().first->I;
    if (!all_of(It.second,
                [&](const std::pair<const AccessInfoTy *, APInt> &It) {
                  return MovePtrOps(
                      IP, It.first->I->getOperand(It.first->PtrOpIdx));
                }))
      continue;
    //errs() << "IT.second size " << It.second.size() << "\n";
    auto *Min = &It.second.front(), *Max = &It.second.front();
    for (auto &Pair : It.second) {
      if (Pair.second.sgt(Max->second))
        Max = &Pair;
      if (Pair.second.slt(Min->second))
        Min = &Pair;
      Pair.first->Checked = true;
    }
    if (Min->second.isNegative())
      CheckAccess(*Min->first, It.first.second, IP, Min->second);
    auto *MaxPtr = CheckAccess(*Max->first, It.first.second, IP, Max->second);
    for (auto &[AI, Offset] : It.second) {
      if (AI == Max->first || (AI == Min->first && Min->second.isNegative()))
        continue;
      IRBuilder<NoFolder> IRB(AI->I);
      auto AccessSize = DL.getTypeStoreSize(AI->I->getAccessType());
      auto *RealPtr = IRB.CreateGEP(
          Int8Ty, MaxPtr,
          {ConstantInt::get(
              Int32Ty, (Offset - AccessSize - Max->second).getSExtValue())});
      AI->I->setOperand(AI->PtrOpIdx, RealPtr);
    }
  }

  for (auto &AI : AccessInfos) {
    auto *FakePtr = AI.I->getOperand(AI.PtrOpIdx);
    bool Checked = AI.Checked;
    for (Instruction *RealPtr : CheckedPtrs.lookup(FakePtr)) {
      if (!DT.dominates(RealPtr->getParent(), AI.I->getParent()))
        continue;
      AI.I->setOperand(AI.PtrOpIdx, RealPtr);
      Checked = true;
    }
    if (Checked)
      continue;

    auto *Size = ConstantInt::get(
        Int32Ty,
        AI.encodeKindInSize(DL.getTypeStoreSize(AI.I->getAccessType())));
    if (FakePtr->getType()->getPointerAddressSpace()) {
      auto *ASC = cast<AddrSpaceCastInst>(FakePtr);
      FakePtr = ASC->getPointerOperand();
    }
    assert(FakePtr->getType()->getPointerAddressSpace() == 0);

    auto *Obj = getUnderlyingObject(FakePtr);
    if (AI.AS == 0)
      AI.AS = Obj->getType()->getPointerAddressSpace();
    if (AI.AS == 0 && isa<Argument>(Obj))
      if (cast<Argument>(Obj)->getParent()->getCallingConv() ==
          CallingConv::AMDGPU_KERNEL)
        AI.AS = 1;
    //    if (AI.AS == 1)
    //      AI.AS = 0;

    Instruction *BaseIP = AI.I->getParent()->getFirstNonPHIOrDbgOrLifetime();

    const auto &PtrInfo = getPtrInfoTy(*Obj, AI, *BaseIP);

    auto *IP = AI.I;
    if (auto *PtrI = dyn_cast<Instruction>(FakePtr))
      if (DT.dominates(PtrI, IP) && PDT.dominates(IP, PtrI))
        IP = PtrI->getNextNode();
    if (Obj == FakePtr && isa<Instruction>(PtrInfo.AS))
      IP = cast<Instruction>(PtrInfo.AS)->getNextNode();

    IRBuilder<NoFolder> IRB(IP);
    SmallVector<Value *> Args;
    Args.append({getPC(IRB), getSourceIndex(*AI.I), FakePtr, Size});

    Args.push_back(PtrInfo.AS);
    Args.push_back(PtrInfo.Start);
    Args.push_back(PtrInfo.Length);
    //getCheckAccessWithInfoFn(AI.AS).getCallee()->dump();
    //getCheckAccessWithInfoFn(AI.AS).getFunctionType()->dump();
    //for (auto *A : Args) {
    //  A->getType()->dump();
    //  A->dump();
    //}
    auto *RealPtr = createCall(IRB, getCheckAccessWithInfoFn(AI.AS), Args);
    AI.I->setOperand(AI.PtrOpIdx, RealPtr);

    assert(RealPtr->getParent());
    CheckedPtrs[FakePtr].push_back(RealPtr);
  }
}

void LightSanitizerImpl::instrumentAllocaInstructions(
    SmallVectorImpl<AllocaInst *> &AllocaInsts) {

  auto IsApplicable = [&](AllocaInst &AI, TypeSize &TS) {
    // Check the type and size.
    if (AI.getAllocatedType()->isScalableTy())
      return false;
    auto AllocSize = AI.getAllocationSize(DL);
    assert(AllocSize && "Alloc size not known!");
    if (AllocSize->getKnownMinValue() >= (1UL << 32))
      return false;
    TS = *AllocSize;
    return true;
  };

  for (auto *AI : AllocaInsts) {
    TypeSize TS(0, false);
    if (!IsApplicable(*AI, TS))
      continue;

    IRBuilder<NoFolder> IRB(AI->getNextNode());
    auto *Size = ConstantInt::get(Int32Ty, TS);
    auto *FakePtr = createCall(IRB, getAllocaRegisterFn(),
                               {getPC(IRB), getSourceIndex(*AI), AI, Size});
    for (auto *U : AI->users()) {
      auto *UI = cast<Instruction>(U);
      if (UI == FakePtr)
        continue;

      if (hasSafeAnnotation(UI))
          continue;

      //if (!isa<AddrSpaceCastInst>(UI)) {
      //  AI->getFunction()->dump();
      //  AI->dump();
      //  UI->dump();
      //}
      assert(isa<AddrSpaceCastInst>(UI) &&
             "Expected only address space casts users of allocas");
      assert(UI->getType()->getPointerAddressSpace() == 0 &&
             "Expected only address space casts to AS 0 as users of allocas");
      UI->replaceAllUsesWith(FakePtr);
    }
  }
}

bool LightSanitizerImpl::instrumentFunction(Function &Fn, SmallVectorImpl<CallInst *> &CallInsts) {
  if (!shouldInstrumentFunction(&Fn))
    return false;

#if 0
  if (Fn.getCallingConv() == CallingConv::AMDGPU_KERNEL)
    Kernels.push_back(&Fn);
#endif

  AllocationInfoMap.clear();

  SmallVector<UnreachableInst *> UnreachableInsts;
  SmallVector<IntrinsicInst *> TrapCalls;
  SmallVector<AllocaInst *> AllocaInsts;
  SmallVector<AccessInfoTy> AccessInfos;
  SmallVector<Instruction *> ASInsts;
  SmallVector<LifetimeIntrinsic *> LifetimeInsts;
  SmallVector<AddrSpaceCastInst *> ASCInsts;

  ReversePostOrderTraversal<Function *> RPOT(&Fn);
  for (auto &It : RPOT) {
    for (auto &I : *It) {
      if (!I.getType()->isVoidTy())
        I.setName("I");

      switch (I.getOpcode()) {
      case Instruction::Unreachable:
        UnreachableInsts.push_back(cast<UnreachableInst>(&I));
        break;
      case Instruction::Alloca:
        AllocaInsts.push_back(cast<AllocaInst>(&I));
        break;
      case Instruction::Store: {
        auto &SI = cast<StoreInst>(I);
        uint32_t Kind = AccessInfoTy::WRITE;
        if (SI.isAtomic())
          Kind |= AccessInfoTy::ATOMIC;
        AccessInfos.push_back({&I, SI.getPointerOperandIndex(),
                               SI.getPointerAddressSpace(), Kind});
        if (isASType(*SI.getPointerOperandType()))
          ASInsts.push_back(&I);
        break;
      }
      case Instruction::Load: {
        auto &LI = cast<LoadInst>(I);
        uint32_t Kind = AccessInfoTy::READ;
        if (LI.isAtomic())
          Kind |= AccessInfoTy::ATOMIC;
        AccessInfos.push_back({&I, LI.getPointerOperandIndex(),
                               LI.getPointerAddressSpace(), Kind});
        if (isASType(*LI.getType()) || isASType(*LI.getPointerOperandType()))
          ASInsts.push_back(&I);
        break;
      }
      case Instruction::AtomicRMW: {
        auto &ARMW = cast<AtomicRMWInst>(I);
        uint32_t Kind =
            AccessInfoTy::READ | AccessInfoTy::WRITE | AccessInfoTy::ATOMIC;
        AccessInfos.push_back({&I, ARMW.getPointerOperandIndex(),
                               ARMW.getPointerAddressSpace(), Kind});
        if (isASType(*ARMW.getType()) ||
            isASType(*ARMW.getPointerOperand()->getType()))
          ASInsts.push_back(&I);
        break;
      }
      case Instruction::AtomicCmpXchg: {
        auto &ACX = cast<AtomicCmpXchgInst>(I);
        uint32_t Kind =
            AccessInfoTy::READ | AccessInfoTy::WRITE | AccessInfoTy::ATOMIC;
        AccessInfos.push_back({&I, ACX.getPointerOperandIndex(),
                               ACX.getPointerAddressSpace(), Kind});
        if (isASType(*ACX.getType()) ||
            isASType(*ACX.getPointerOperand()->getType()))
          ASInsts.push_back(&I);
        break;
      }
      case Instruction::Call: {
        auto &CI = cast<CallInst>(I);
        if (CI.isIndirectCall())
          AmbiguousCalls.insert(&CI);
        bool Handled = false;
        if (auto *II = dyn_cast<IntrinsicInst>(&CI)) {
          switch (II->getIntrinsicID()) {
          case Intrinsic::trap:
            Handled = true;
            TrapCalls.push_back(II);
            break;
          case Intrinsic::lifetime_start:
          case Intrinsic::lifetime_end:
            Handled = true;
            LifetimeInsts.push_back(cast<LifetimeIntrinsic>(II));
            break;
          }
        }
        if (!Handled)
          CallInsts.push_back(&CI);
        if (isASType(*CI.getType()))
          ASInsts.push_back(&I);
        else if (any_of(CI.args(),
                        [&](Value *Op) { return isASType(*Op->getType()); }))
          ASInsts.push_back(&I);
        break;
      }
      case Instruction::AddrSpaceCast:
        ASCInsts.push_back(cast<AddrSpaceCastInst>(&I));
        ASInsts.push_back(&I);
        break;
      case Instruction::GetElementPtr:
        if (isASType(*I.getType()))
          ASInsts.push_back(&I);
        break;
      default:
        if (isASType(*I.getType()))
          ASInsts.push_back(&I);
        else if (any_of(I.operand_values(),
                        [&](Value *Op) { return isASType(*Op->getType()); }))
          ASInsts.push_back(&I);
        break;
      }
    }
  }

  DominatorTree DT(Fn);
  PostDominatorTree PDT(Fn);

#if 0
  removeAS(Fn, ASInsts);
#endif
  instrumentLifetimeIntrinsics(LifetimeInsts);
  instrumentTrapInsts(TrapCalls);
  instrumentUnreachableInsts(UnreachableInsts);
  instrumentAccesses(DT, PDT, AccessInfos);
  instrumentAllocaInstructions(AllocaInsts);

  RTCalls.clear();

  auto &EntryBB = Fn.getEntryBlock();
  SmallVector<AllocaInst *> Allocas;
  for (auto &BB : Fn)
    for (auto &I : BB)
      if (auto *AI = dyn_cast<AllocaInst>(&I))
        Allocas.push_back(AI);
  for (auto *AI : Allocas)
    AI->moveBefore(&*EntryBB.getFirstInsertionPt());

  return true;
}

bool LightSanitizerImpl::instrumentMainFunction()
{
  auto *OrigMainFn = M.getFunction("main");
  if (!shouldInstrumentFunction(OrigMainFn))
    return false;

  OrigMainFn->setName("__ligthsan_main");

  Function *NewMainFn = Function::Create(OrigMainFn->getFunctionType(), GlobalValue::ExternalLinkage, "main", M);
  NewMainFn->addFnAttr(Attribute::DisableSanitizerInstrumentation);

  auto *EntryBB = BasicBlock::Create(Ctx, "entry", NewMainFn);
  IRBuilder<NoFolder> IRB(EntryBB, EntryBB->getFirstNonPHIOrDbgOrAlloca());

  SmallVector<Value *> Args;
  for (Argument &Arg : NewMainFn->args())
    Args.push_back(&Arg);

  if (Args.size() > 0) {
    Args[1] = createCall(IRB, getMainArgsRegisterFn(),
                               {getPC(IRB), ConstantInt::get(Int64Ty, 0), Args[0], Args[1]});
  }

  FunctionCallee FnCallee = M.getOrInsertFunction("__ligthsan_main", OrigMainFn->getFunctionType());

  ArrayRef<Value *> ArrayRefArgs(Args);
  auto *Ret = IRB.CreateCall(FnCallee, ArrayRefArgs);
  IRB.CreateRet(Ret);

  return true;
}

bool LightSanitizerImpl::handleAmbiguousCalls() {
  if (AmbiguousCalls.empty())
    return false;

  SmallVector<CallBase *> AmbiguousCallsOrdered;
  SmallVector<Constant *> AmbiguousCallsMapping;
  for (size_t I = 0; I < AmbiguousCalls.size(); ++I) {
    CallBase &CB = *AmbiguousCalls[I];
    AmbiguousCallsOrdered.push_back(&CB);
    AmbiguousCallsMapping.push_back(getSourceIndex(CB));
  }

  uint64_t AmbiguousCallsBitWidth =
      llvm::Log2_64_Ceil(AmbiguousCalls.size() + 1);

  new GlobalVariable(M, Int64Ty, /*isConstant=*/true,
                     GlobalValue::ExternalLinkage,
                     ConstantInt::get(Int64Ty, AmbiguousCallsBitWidth),
                     "__lightsan_num_ambiguous_calls", nullptr,
                     GlobalValue::ThreadLocalMode::NotThreadLocal, 1);

  size_t NumAmbiguousCalls = AmbiguousCalls.size();
  {
    auto *ArrayTy = ArrayType::get(Int64Ty, NumAmbiguousCalls);
    auto *GV = new GlobalVariable(
        M, ArrayTy, /*isConstant=*/true, GlobalValue::ExternalLinkage,
        ConstantArray::get(ArrayTy, AmbiguousCallsMapping),
        "__lightsan_ambiguous_calls_mapping", nullptr,
        GlobalValue::ThreadLocalMode::NotThreadLocal, 4);
    GV->setVisibility(GlobalValue::ProtectedVisibility);
  }

  auto *ArrayTy = ArrayType::get(Int64Ty, 1024);
  LocationsArray = new GlobalVariable(
      M, ArrayTy, /*isConstant=*/false, GlobalValue::PrivateLinkage,
      UndefValue::get(ArrayTy), "__lightsan_calls", nullptr,
      GlobalValue::ThreadLocalMode::NotThreadLocal, SharedAS);

  for (const auto &It : llvm::enumerate(AmbiguousCallsOrdered)) {
    IRBuilder<NoFolder> IRB(It.value());
    Value *Idx = createCall(IRB, getThreadIdFn(), {}, "san.gtid");
    Value *Ptr = IRB.CreateGEP(Int64Ty, LocationsArray, {Idx});
    Value *OldVal = IRB.CreateLoad(Int64Ty, Ptr);
    Value *OldValShifted = IRB.CreateShl(
        OldVal, ConstantInt::get(Int64Ty, AmbiguousCallsBitWidth));
    Value *NewVal = IRB.CreateBinOp(Instruction::Or, OldValShifted,
                                    ConstantInt::get(Int64Ty, It.index() + 1));
    IRB.CreateStore(NewVal, Ptr);
    IRB.SetInsertPoint(It.value()->getNextNode());
    IRB.CreateStore(OldVal, Ptr);
  }

  return true;
}

#if 0
bool LightSanitizerImpl::handleCallStackSupport() {
  if (LocationMap.empty())
    return false;

  auto *NamesTy = ArrayType::get(Int8Ty, ConcatenatedString.size() + 1);
  auto *Names = new GlobalVariable(
      M, NamesTy, /*isConstant=*/true, GlobalValue::ExternalLinkage,
      ConstantDataArray::getString(Ctx, ConcatenatedString),
      "__lightsan_location_names", nullptr,
      GlobalValue::ThreadLocalMode::NotThreadLocal, 4);
  Names->setVisibility(GlobalValue::ProtectedVisibility);

  auto *ArrayTy = ArrayType::get(Int64Ty, LocationEncoding.size());
  auto *GV = new GlobalVariable(
      M, ArrayTy, /*isConstant=*/true, GlobalValue::ExternalLinkage,
      ConstantArray::get(ArrayTy, LocationEncoding), "__lightsan_locations",
      nullptr, GlobalValue::ThreadLocalMode::NotThreadLocal, 4);
  GV->setVisibility(GlobalValue::ProtectedVisibility);

  return true;
}
#endif

void LightSanitizerImpl::instrumentGlobal(IRBuilder<NoFolder> &IRB,
                                            GlobalVariable &GV, uint32_t AS) {
  if (!canInstrumentGlobal(GV))
    return;

  auto InsertNewInst = [&](Use &U, Instruction *UserI,
                           SmallVectorImpl<Instruction *> &NewInsts,
                           ValueToValueMapTy &VMap) -> Instruction * {
    auto *IP = UserI;
    if (auto *PHI = dyn_cast<PHINode>(UserI))
      IP = PHI->getIncomingBlock(U)->getTerminator();

    SmallVector<Instruction *> CloneInsts;
    for (auto *NewI : NewInsts) {
      auto *CloneI = NewI->clone();
      CloneInsts.push_back(CloneI);
      CloneI->insertBefore(IP);
      CloneI->setName("i");
      VMap[VMap[NewI]] = CloneI;
      RemapInstruction(CloneI, VMap, RF_IgnoreMissingLocals);
    }
    U.set(VMap[VMap[NewInsts.back()]]);
#if 0
    removeAS(*IP->getFunction(), CloneInsts);
#endif
    if (isa<AddrSpaceCastInst>(NewInsts.front()))
      return nullptr;
    return cast<Instruction>(VMap[VMap[NewInsts.front()]]);
  };

  auto ConstantExprToInst = [&](Use *CEU, ConstantExpr *CE,
                                SmallVectorImpl<Use *> &ToBeReplacedUses) {
    SmallVector<Instruction *> NewInsts;
    SmallVector<ConstantExpr *> Worklist;
    Worklist.push_back(CE);

    ValueToValueMapTy VMap;
    while (!Worklist.empty()) {
      ConstantExpr *CE = Worklist.pop_back_val();
      auto *NewI = CE->getAsInstruction();
      NewInsts.push_back(NewI);
      VMap[NewI] = CE;
      for (auto &U : make_early_inc_range(CE->uses())) {
        if (auto *UserI = dyn_cast<Instruction>(U.getUser())) {
          if (shouldInstrumentFunction(UserI->getFunction())) {
            if (auto *NewI = InsertNewInst(U, UserI, NewInsts, VMap))
              ToBeReplacedUses.push_back(
                  &NewI->getOperandUse(CEU->getOperandNo()));
          }
          continue;
        }
        if (auto *UserCE = dyn_cast<ConstantExpr>(U.getUser())) {
          Worklist.push_back(UserCE);
          continue;
        }
        if (auto *GV = dyn_cast<GlobalVariable>(U.getUser())) {
          auto *SI = IRB.CreateStore(CE, GV);
          if (auto *NewI =
                  InsertNewInst(SI->getOperandUse(0), SI, NewInsts, VMap))
            ToBeReplacedUses.push_back(
                &NewI->getOperandUse(CEU->getOperandNo()));
          continue;
        }
        if (isa<Constant>(U.getUser())) {
          continue;
        }

        llvm_unreachable("unhandled user");
      }
    }
    for (auto *NewInst : NewInsts)
      NewInst->deleteValue();
  };

  //errs() << "processing global variable \n";
  //GV.dump();

  auto *ShadowGV = new GlobalVariable(
      M, PtrTy, false, GlobalValue::PrivateLinkage, PoisonValue::get(PtrTy),
      getShadowGlobalName(GV), &GV, GlobalValue::NotThreadLocal, 0);

  auto *Size =
      ConstantInt::get(Int64Ty, DL.getTypeAllocSize(GV.getValueType()));

  auto *FakePtr = createCall(IRB, getGlobalRegisterFn(0),
                             {getPC(IRB), getSourceIndex(&GV), &GV, Size});
  IRB.CreateStore(FakePtr, ShadowGV);

  //errs() << "processing its uses\n";

  SmallVector<Use *> ToBeReplacedUses;
  for (auto &U : GV.uses()) {
    if (auto *UserI = dyn_cast<Instruction>(U.getUser())) {
      //UserI->dump();
      if (shouldInstrumentFunction(UserI->getFunction()))
        ToBeReplacedUses.push_back(&U);
    } else if (auto *CE = dyn_cast<ConstantExpr>(U.getUser())) {
      ConstantExprToInst(&U, CE, ToBeReplacedUses);
    } else {
      //errs() << "unhandled user of global variable\n";
      llvm_unreachable("unhandled user");
    }
  }

  for (auto *U : ToBeReplacedUses) {
    auto *IP = cast<Instruction>(U->getUser());
    if (hasSafeAnnotation(IP))
      continue;

    if (auto *PHI = dyn_cast<PHINode>(IP))
      IP = PHI->getIncomingBlock(*U)->getTerminator();

    IRBuilder<NoFolder> IRB(IP);
    auto *FakePtr = IRB.CreateLoad(PtrTy, ShadowGV);
    //errs() << *FakePtr << " :: " << *U->get() << " : : " << *U->getUser()
    //       << "\n";
    if (U->get()->getType() == FakePtr->getType()) {
      U->set(FakePtr);
      continue;
    }
    auto *ASC = dyn_cast<AddrSpaceCastInst>(U->getUser());
    if (!ASC || ASC->getDestAddressSpace()) {
      //IP->getFunction()->dump();
      //U->getUser()->dump();
      //U->get()->dump();
      llvm_unreachable("Expected addrspacecast to AS(0) only");
    }
    ASC->replaceAllUsesWith(FakePtr);
  }
}

#if 0
Function *LightSanitizerImpl::createSanitizerInitKernel() {
  if (auto *Fn = M.getFunction("__lightsan_init_kernel"))
    return Fn;

  Function *InitSharedFn = Function::Create(FunctionType::get(VoidTy, false),
                                            GlobalValue::PrivateLinkage,
                                            "__lightsan_init_kernel", &M);
  InitSharedFn->addFnAttr(Attribute::DisableSanitizerInstrumentation);

  auto *EntryBB = BasicBlock::Create(Ctx, "entry", InitSharedFn);
  IRBuilder<NoFolder> IRB(EntryBB, EntryBB->getFirstNonPHIOrDbgOrAlloca());
  auto *Barrier = createCall(IRB, getSyncBlockFn());
  IRB.CreateRetVoid();
  IRB.SetInsertPoint(Barrier);

  if (!AmbiguousCalls.empty()) {
    Value *Idx = createCall(IRB, getThreadIdFn(), {}, "san.gtid");
    Value *Ptr = IRB.CreateGEP(Int64Ty, LocationsArray, {Idx});
    IRB.CreateStore(ConstantInt::get(Int64Ty, 0), Ptr);

    auto *CondV = IRB.CreateICmpEQ(Idx, IRB.getInt32(0));

    auto *CondTI = SplitBlockAndInsertIfThen(CondV, Barrier, false);
    IRB.SetInsertPoint(CondTI);
    auto *AmbiguousCallsInfoPtrGV =
        M.getNamedGlobal("__lightsan_ambiguous_calls_info_ptr");
    assert(AmbiguousCallsInfoPtrGV);
    IRB.CreateStore(LocationsArray, AmbiguousCallsInfoPtrGV);
  }

  for (auto &GV : M.globals()) {
    if (GV.getAddressSpace() != SharedAS)
      continue;

    instrumentGlobal(IRB, GV, SharedAS);
  }

  return InitSharedFn;
}

bool LightSanitizerImpl::finalizeKernels() {
  for (auto *Kernel : Kernels) {
    Function *InitKernelFn = createSanitizerInitKernel();
    IRBuilder<NoFolder> IRB(
        &*Kernel->getEntryBlock().getFirstNonPHIOrDbgOrAlloca());
    createCall(IRB, InitKernelFn, {});
  }
  return Kernels.size();
}
#endif

bool LightSanitizerImpl::addCtor() {
  Function *CtorFn =
      Function::Create(FunctionType::get(VoidTy, false),
                       GlobalValue::PrivateLinkage, "__lightsan_ctor", &M);
  CtorFn->addFnAttr(Attribute::DisableSanitizerInstrumentation);

  BasicBlock *Entry = BasicBlock::Create(Ctx, "entry", CtorFn);
  IRBuilder<NoFolder> IRB(Entry);

  for (auto &GV : M.globals())
    instrumentGlobal(IRB, GV, GlobalAS);

  IRB.CreateRetVoid();

  appendToGlobalCtors(M, CtorFn, 0, nullptr);
  return true;
}

bool LightSanitizerImpl::addDtor() {
  Function *DtorFn =
      Function::Create(FunctionType::get(VoidTy, false),
                       GlobalValue::PrivateLinkage, "__lightsan_dtor", &M);
  DtorFn->addFnAttr(Attribute::DisableSanitizerInstrumentation);
  BasicBlock *Entry = BasicBlock::Create(Ctx, "entry", DtorFn);
  IRBuilder<NoFolder> IRB(Entry);

  createCall(IRB, getLeakCheckFn());

  IRB.CreateRetVoid();
  appendToGlobalDtors(M, DtorFn, 0, nullptr);
  return true;
}

bool LightSanitizerImpl::instrument() {
  bool Changed = false;

  for (auto &GV : M.globals())
    convertUsersOfConstantsToInstructions({&GV});

  SmallVector<CallInst *> CallInsts;

  for (Function &Fn : M)
    Changed |= instrumentFunction(Fn, CallInsts);

  handleAmbiguousCalls();

  Changed |= addCtor();
  Changed |= addDtor();
  //Changed |= finalizeKernels();
  //Changed |= handleCallStackSupport();

  // Instrument call instructions after accesses and globals
  instrumentCallInsts(CallInsts);

  Changed |= instrumentMainFunction();

  removeFromUsedLists(M, [&](Constant *C) {
    if (!C->getName().starts_with("__lightsan_"))
      return false;
    return Changed = true;
  });

  return Changed;
}

PreservedAnalyses LightSanitizerPass::run(Module &M,
                                            ModuleAnalysisManager &AM) {
  errs() << "[LightSan] starting pass\n";

  errs() << "=================================================\n";
  errs() << "[LightSan] module before the pass:\n";
  M.dump();

  FunctionAnalysisManager &FAM =
      AM.getResult<FunctionAnalysisManagerModuleProxy>(M).getManager();
  LightSanitizerImpl Impl(M, FAM);
  if (!Impl.instrument())
    return PreservedAnalyses::all();

  assert(!verifyModule(M, &errs()));

  errs() << "[LightSan] finishing pass\n";

  return PreservedAnalyses::none();
}
