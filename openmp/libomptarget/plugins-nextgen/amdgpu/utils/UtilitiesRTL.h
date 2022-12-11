//===----RTLs/amdgpu/utils/UtilitiesRTL.h ------------------------- C++ -*-===//
//
// Part of the LLVM Project, under the Apache License v2.0 with LLVM Exceptions.
// See https://llvm.org/LICENSE.txt for license information.
// SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception
//
//===----------------------------------------------------------------------===//
//
// RTL Utilities for AMDGPU plugins
//
//===----------------------------------------------------------------------===//

#include <cstdint>
#include <hsa.h>
#include <hsa_ext_amd.h>
#include <string>

#include "Debug.h"
#include "omptarget.h"

#include "llvm/ADT/StringMap.h"
#include "llvm/ADT/StringRef.h"

namespace llvm {
namespace omp {
namespace target {
namespace plugin {
namespace utils {

// The implicit arguments of AMDGPU kernels.
typedef struct impl_implicit_args_s {
  uint64_t offset_x;
  uint64_t offset_y;
  uint64_t offset_z;
  uint64_t hostcall_ptr;
  uint64_t unused0;
  uint64_t unused1;
  uint64_t unused2;
} impl_implicit_args_t;

static_assert(sizeof(impl_implicit_args_t) == 56, "Unexpected size of implicit arguments");

/// Parse a TargetID to get processor arch and feature map.
/// Returns processor subarch.
/// Returns TargetID features in \p FeatureMap argument.
/// If the \p TargetID contains feature+, FeatureMap it to true.
/// If the \p TargetID contains feature-, FeatureMap it to false.
/// If the \p TargetID does not contain a feature (default), do not map it.
StringRef parseTargetID(StringRef TargetID, StringMap<bool> &FeatureMap) {
  if (TargetID.empty())
    return llvm::StringRef();

  auto ArchFeature = TargetID.split(":");
  auto Arch = ArchFeature.first;
  auto Features = ArchFeature.second;
  if (Features.empty())
    return Arch;

  if (Features.contains("sramecc+")) {
    FeatureMap.insert(std::pair<StringRef, bool>("sramecc", true));
  } else if (Features.contains("sramecc-")) {
    FeatureMap.insert(std::pair<StringRef, bool>("sramecc", false));
  }
  if (Features.contains("xnack+")) {
    FeatureMap.insert(std::pair<StringRef, bool>("xnack", true));
  } else if (Features.contains("xnack-")) {
    FeatureMap.insert(std::pair<StringRef, bool>("xnack", false));
  }

  return Arch;
}

/// Check if an image is compatible with current system's environment.
bool isImageCompatibleWithEnv(__tgt_image_info *Info,
                              const std::string &EnvInfo) {
  llvm::StringRef ImgTID(Info->Arch), EnvTID(EnvInfo);

  // Compatible in case of exact match.
  if (ImgTID == EnvTID) {
    DP("Compatible: Exact match \t[Image: %s]\t:\t[Environment: %s]\n",
       ImgTID.data(), EnvTID.data());
    return true;
  }

  // Incompatible if Archs mismatch.
  StringMap<bool> ImgMap, EnvMap;
  StringRef ImgArch = utils::parseTargetID(ImgTID, ImgMap);
  StringRef EnvArch = utils::parseTargetID(EnvTID, EnvMap);

  // Both EnvArch and ImgArch can't be empty here.
  if (EnvArch.empty() || ImgArch.empty() || !ImgArch.contains(EnvArch)) {
    DP("Incompatible: Processor mismatch \t[Image: %s]\t:\t[Environment: "
       "%s]\n",
       ImgTID.data(), EnvTID.data());
    return false;
  }

  // Incompatible if image has more features than the environment,
  // irrespective of type or sign of features.
  if (ImgMap.size() > EnvMap.size()) {
    DP("Incompatible: Image has more features than the environment \t[Image: "
       "%s]\t:\t[Environment: %s]\n",
       ImgTID.data(), EnvTID.data());
    return false;
  }

  // Compatible if each target feature specified by the environment is
  // compatible with target feature of the image. The target feature is
  // compatible if the iamge does not specify it (meaning Any), or if it
  // specifies it with the same value (meaning On or Off).
  for (const auto &ImgFeature : ImgMap) {
    auto EnvFeature = EnvMap.find(ImgFeature.first());
    if (EnvFeature == EnvMap.end()) {
      DP("Incompatible: Value of Image's non-ANY feature is not matching "
         "with "
         "the Environment feature's ANY value \t[Image: "
         "%s]\t:\t[Environment: "
         "%s]\n",
         ImgTID.data(), EnvTID.data());
      return false;
    }

    if (EnvFeature->first() == ImgFeature.first() && EnvFeature->second != ImgFeature.second) {
      DP("Incompatible: Value of Image's non-ANY feature is not matching "
         "with "
         "the Environment feature's non-ANY value \t[Image: "
         "%s]\t:\t[Environment: %s]\n",
         ImgTID.data(), EnvTID.data());
      return false;
    }
  }

  // Image is compatible if all features of Environment are:
  //   - either, present in the Image's features map with the same sign,
  //   - or, the feature is missing from Image's features map i.e. it is
  //   set to ANY
  DP("Compatible: Target IDs are compatible \t[Image: %s]\t:\t[Environment: "
     "%s]\n",
     ImgTID.data(), EnvTID.data());
  return true;
}

} // namespace utils
} // namespace plugin
} // namespace target
} // namespace omp
} // namespace llvm
