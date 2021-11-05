/*
  Copyright (c) 2019-present, Trail of Bits, Inc.
  All rights reserved.

  This source code is licensed in accordance with the terms specified in
  the LICENSE file found in the root directory of this source tree.
*/

#pragma once

#include <memory>

#include <llvm/IR/DerivedTypes.h>
#include <llvm/IR/Module.h>

#include <tob/ebpf/iperfevent.h>

namespace tob::ebpf {
class TracepointPerfEvent final : public IPerfEvent {
  struct PrivateData;
  std::unique_ptr<PrivateData> d;

public:
  virtual ~TracepointPerfEvent() override;

  virtual Type type() const override;
  virtual int fd() const override;

  virtual bool isKprobeSyscall() const override;
  virtual bool useKprobeIndirectPtRegs() const override;

protected:
  TracepointPerfEvent(const std::string &category, const std::string &name,
                      std::int32_t process_id);

  friend class IPerfEvent;
};
} // namespace tob::ebpf
