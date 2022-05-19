/*
  Copyright (c) 2019-present, Trail of Bits, Inc.
  All rights reserved.

  This source code is licensed in accordance with the terms specified in
  the LICENSE file found in the root directory of this source tree.
*/

#pragma once

#include <linux/bpf.h>

namespace tob::ebpf {

class FeatureDetection {
public:
  static bool isHelperImplemented(bpf_func_id id);
};

} // namespace tob::ebpf
