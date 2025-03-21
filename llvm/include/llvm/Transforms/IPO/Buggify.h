//===- Transforms/IPO/Buggify.h ------------------------------------------===//
//
// Part of the LLVM Project, under the Apache License v2.0 with LLVM Exceptions.
// See https://llvm.org/LICENSE.txt for license information.
// SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception
//
//===----------------------------------------------------------------------===//
//
// A pass that adds memory-related bugs to test sanitizers.
//
//===----------------------------------------------------------------------===//

#ifndef LLVM_TRANSFORMS_IPO_BUGGIFY_H
#define LLVM_TRANSFORMS_IPO_BUGGIFY_H

#include "llvm/IR/PassManager.h"
#include "llvm/Pass.h"

namespace llvm {

class BuggifyPass : public PassInfoMixin<BuggifyPass> {
public:
  BuggifyPass() {}
  PreservedAnalyses run(Module &M, ModuleAnalysisManager &AM);
};

} // end namespace llvm

#endif // LLVM_TRANSFORMS_IPO_BUGGIFY_H
