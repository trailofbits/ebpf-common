/*
  Copyright (c) 2019-present, Trail of Bits, Inc.
  All rights reserved.

  This source code is licensed in accordance with the terms specified in
  the LICENSE file found in the root directory of this source tree.
*/

#pragma once

#include <memory>

#include <tob/ebpf/ievent.h>

namespace tob::ebpf {
class KprobeEvent final : public IEvent {
  struct PrivateData;
  std::unique_ptr<PrivateData> d;

public:
  virtual ~KprobeEvent() override;

  virtual Type type() const override;
  virtual int fd() const override;
  virtual std::string name() const override;

  virtual bool isSyscallKprobe() const override;
  virtual bool usesKprobeIndirectPtRegs() const override;

protected:
  KprobeEvent(const std::string &name, bool ret_probe, bool is_syscall,
              std::int32_t process_id);

  friend class IEvent;
};
} // namespace tob::ebpf
