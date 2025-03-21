//===-- Buggify.cpp - Bug adding pass -------------------------------------===//
//
// Part of the LLVM Project, under the Apache License v2.0 with LLVM Exceptions.
// See https://llvm.org/LICENSE.txt for license information.
// SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception
//
//===----------------------------------------------------------------------===//
//
//===----------------------------------------------------------------------===//

#include "llvm/Transforms/IPO/Buggify.h"

#include "llvm/ADT/STLExtras.h"
#include "llvm/ADT/STLFunctionalExtras.h"
#include "llvm/ADT/SmallVector.h"
#include "llvm/ADT/iterator.h"
#include "llvm/Analysis/CaptureTracking.h"
#include "llvm/Analysis/DomTreeUpdater.h"
#include "llvm/Analysis/LoopInfo.h"
#include "llvm/Analysis/MemoryBuiltins.h"
#include "llvm/Analysis/PostDominators.h"
#include "llvm/Analysis/ScalarEvolution.h"
#include "llvm/Analysis/ScalarEvolutionExpressions.h"
#include "llvm/Analysis/TargetLibraryInfo.h"
#include "llvm/Analysis/ValueTracking.h"
#include "llvm/ExecutionEngine/GenericValue.h"
#include "llvm/IR/Argument.h"
#include "llvm/IR/BasicBlock.h"
#include "llvm/IR/Constants.h"
#include "llvm/IR/DataLayout.h"
#include "llvm/IR/DerivedTypes.h"
#include "llvm/IR/Dominators.h"
#include "llvm/IR/GEPNoWrapFlags.h"
#include "llvm/IR/GlobalValue.h"
#include "llvm/IR/GlobalVariable.h"
#include "llvm/IR/IRBuilder.h"
#include "llvm/IR/Instruction.h"
#include "llvm/IR/Instructions.h"
#include "llvm/IR/IntrinsicInst.h"
#include "llvm/IR/Intrinsics.h"
#include "llvm/IR/Module.h"
#include "llvm/IR/Operator.h"
#include "llvm/IR/PassManager.h"
#include "llvm/IR/Verifier.h"
#include "llvm/Pass.h"
#include "llvm/Support/Casting.h"
#include "llvm/Support/Debug.h"
#include "llvm/Support/ErrorHandling.h"
#include "llvm/Transforms/IPO/AlwaysInliner.h"
#include "llvm/Transforms/IPO/Attributor.h"
#include "llvm/Transforms/IPO/Instrumentor.h"
#include "llvm/Transforms/InstCombine/InstCombine.h"
#include "llvm/Transforms/Scalar/GVN.h"
#include "llvm/Transforms/Scalar/SROA.h"
#include "llvm/Transforms/Scalar/SimplifyCFG.h"
#include "llvm/Transforms/Utils/BasicBlockUtils.h"
#include "llvm/Transforms/Utils/ModuleUtils.h"
#include "llvm/Transforms/Utils/PromoteMemToReg.h"
#include "llvm/Transforms/Utils/ScalarEvolutionExpander.h"
#include "llvm/Transforms/Utils/SimplifyCFGOptions.h"
#include "llvm/Transforms/Utils/ValueMapper.h"
#include <cassert>
#include <cstdint>
#include <functional>

using namespace llvm;
using namespace llvm::instrumentor;

#define DEBUG_TYPE "buggify"

static cl::opt<std::string>
    BuggifyRuntimeBitcode("buggify-runtime-bitcode",
                         cl::desc("Read runtime bitcode to be linked in, "
                                  "alwaysinline functions are inlined"),
                         cl::init(""));

static cl::opt<bool> PrintModule(
    "buggify-print-module",
    cl::desc(
        "Print the module before and after the buggify pass"),
    cl::init(false));

static constexpr char BuggifyRuntimePrefix[] = "__buggify_";

namespace {

struct BuggifyImpl;

struct BuggifyInstrumentationConfig : public InstrumentationConfig {
  BuggifyInstrumentationConfig(BuggifyImpl &BI, Module &M);
  virtual ~BuggifyInstrumentationConfig() {}

  void populate(InstrumentorIRBuilderTy &IRB) override;

private:
  BuggifyImpl &BI;
};

struct BuggifyImpl {
  BuggifyImpl(Module &M, ModuleAnalysisManager &MAM)
    : M(M), MAM(MAM),
      FAM(MAM.getResult<FunctionAnalysisManagerModuleProxy>(M).getManager()),
      IConf(*this, M), IIRB(M, FAM) {}

  bool instrument();

  bool shouldInstrumentCall(CallInst &CI);
  bool shouldInstrumentFunction(Function &Fn);
  bool shouldInstrumentLoad(LoadInst &LI);
  bool shouldInstrumentStore(StoreInst &SI);
  bool shouldInstrumentAlloca(AllocaInst &AI);

private:
  Module &M;
  ModuleAnalysisManager &MAM;
  FunctionAnalysisManager &FAM;
  BuggifyInstrumentationConfig IConf;
  InstrumentorIRBuilderTy IIRB;
  const DataLayout &DL = M.getDataLayout();
};

bool BuggifyImpl::shouldInstrumentCall(CallInst &CI) { return true; }

bool BuggifyImpl::shouldInstrumentFunction(Function &Fn) { return true; }

bool BuggifyImpl::shouldInstrumentLoad(LoadInst &LI) { return true; }

bool BuggifyImpl::shouldInstrumentStore(StoreInst &SI) { return true; }

bool BuggifyImpl::shouldInstrumentAlloca(AllocaInst &AI) { return true; }

bool BuggifyImpl::instrument() {
  bool Changed = false;

  InstrumentorPass IP(&IConf, &IIRB);
  auto PA = IP.run(M, MAM);
  if (!PA.areAllPreserved())
    Changed = true;

  return Changed;
}

BuggifyInstrumentationConfig::BuggifyInstrumentationConfig(BuggifyImpl &Impl,
                                                           Module &M)
    : InstrumentationConfig(), BI(Impl) {
  ReadConfig = false;
  RuntimePrefix->setString(BuggifyRuntimePrefix);
  DemangleFunctionNames->setBool(true);
  RuntimeStubsFile->setString("buggify_rt_stub.c");
  RuntimeBitcode->setString(BuggifyRuntimeBitcode);
  InlineRuntimeEagerly->setBool(false);
}

void BuggifyInstrumentationConfig::populate(InstrumentorIRBuilderTy &IIRB) {
  //BasePointerIO::ConfigTy BPIOConfig(/*Enable=*/false);
  //BPIOConfig.set(BasePointerIO::PassPointer);
  //BPIOConfig.set(BasePointerIO::PassPointerKind);
  //BasePointerIO::populate(*this, IIRB.Ctx, &BPIOConfig);

  //CallIO::ConfigTy CICConfig(/*Enable=*/false);
  //CICConfig.set(CallIO::PassCallee);
  //CICConfig.set(CallIO::PassNumParameters);
  //CICConfig.set(CallIO::PassParameters);
  //CICConfig.ArgFilter = [&](Use &Op) {
  //  return Op->getType()->isPointerTy() && !isa<ConstantPointerNull>(Op) &&
  //         !isa<UndefValue>(Op);
  //};
  //auto *PreCIC = InstrumentationConfig::allocate<CallIO>(/*IsPRE=*/true);
  //PreCIC->CB = [&](Value &V) {
  //  return BI.shouldInstrumentCall(cast<CallInst>(V));
  //};
  //PreCIC->init(*this, IIRB.Ctx, &CICConfig);

  LoadIO::ConfigTy LICConfig(/*Enable=*/false);
  LICConfig.set(LoadIO::PassPointer);
  LICConfig.set(LoadIO::ReplacePointer);
  //LICConfig.set(LoadIO::PassBasePointerInfo);
  LICConfig.set(LoadIO::PassValueSize);
  auto *LIC = InstrumentationConfig::allocate<LoadIO>(/*IsPRE=*/true);
  LIC->HoistKind = DO_NOT_HOIST;
  LIC->CB = [&](Value &V) {
    return BI.shouldInstrumentLoad(cast<LoadInst>(V));
  };
  LIC->init(*this, IIRB, &LICConfig);

  StoreIO::ConfigTy SICConfig(/*Enable=*/false);
  SICConfig.set(StoreIO::PassPointer);
  SICConfig.set(StoreIO::ReplacePointer);
  //SICConfig.set(StoreIO::PassBasePointerInfo);
  SICConfig.set(StoreIO::PassStoredValueSize);
  auto *SIC = InstrumentationConfig::allocate<StoreIO>(/*IsPRE=*/true);
  SIC->HoistKind = DO_NOT_HOIST;
  SIC->CB = [&](Value &V) {
    return BI.shouldInstrumentStore(cast<StoreInst>(V));
  };
  SIC->init(*this, IIRB, &SICConfig);

  //FunctionIO::ConfigTy FICConfig(/*Enable=*/false);
  //FICConfig.set(FunctionIO::PassName);
  //FICConfig.set(FunctionIO::PassAddress);
  //FICConfig.set(FunctionIO::PassNumArguments);
  //FICConfig.set(FunctionIO::PassArguments);
  //FICConfig.set(FunctionIO::ReplaceArguments);
  //auto *FIC = InstrumentationConfig::allocate<FunctionIO>(/*IsPRE=*/true);
  //FIC->CB = [&](Value &V) {
  //  return BI.shouldInstrumentFunction(cast<Function>(V));
  //};
  //FIC->init(*this, IIRB.Ctx, &FICConfig);

  AllocaIO::ConfigTy PreAICConfig(/*Enable=*/false);
  PreAICConfig.set(AllocaIO::PassSize);
  PreAICConfig.set(AllocaIO::ReplaceSize);
  PreAICConfig.set(AllocaIO::PassId);
  auto *PreAIC = InstrumentationConfig::allocate<AllocaIO>(/*IsPRE=*/true);
  PreAIC->CB = [&](Value &V) {
    return BI.shouldInstrumentAlloca(cast<AllocaInst>(V));
  };
  PreAIC->init(*this, IIRB.Ctx, &PreAICConfig);

  AllocaIO::ConfigTy PostAICConfig(/*Enable=*/false);
  PostAICConfig.set(AllocaIO::PassAddress);
  PostAICConfig.set(AllocaIO::PassSize);
  PostAICConfig.set(AllocaIO::PassId);
  auto *PostAIC = InstrumentationConfig::allocate<AllocaIO>(/*IsPRE=*/false);
  PostAIC->CB = [&](Value &V) {
    return BI.shouldInstrumentAlloca(cast<AllocaInst>(V));
  };
  PostAIC->init(*this, IIRB.Ctx, &PostAICConfig);
}

} // namespace

PreservedAnalyses BuggifyPass::run(Module &M, AnalysisManager<Module> &MAM) {
  errs() << "running buggify pass\n";

  if (PrintModule) {
    errs() << "========== before buggify ==========\n";
    M.dump();
    errs() << "====================================\n";
  }

  BuggifyImpl Impl(M, MAM);

  bool Changed = Impl.instrument();
  if (!Changed)
    return PreservedAnalyses::all();

  if (verifyModule(M))
    M.dump();

  assert(!verifyModule(M, &errs()));

  if (PrintModule) {
    errs() << "========== after buggify ===========\n";
    M.dump();
    errs() << "====================================\n";
  }

  return PreservedAnalyses::none();
}
