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
class LSMEvent final : public IEvent {
  struct PrivateData;
  std::unique_ptr<PrivateData> d;

public:
  virtual ~LSMEvent() override;

  virtual Type type() const override;
  virtual std::string name() const override;

  void setFileDescriptor(int fd);
  virtual int fd() const override;

  virtual bool isSyscallKprobe() const override;
  virtual bool usesKprobeIndirectPtRegs() const override;

  std::uint32_t btfTypeID() const;

protected:
  LSMEvent(const std::filesystem::path &btf_path, const std::string &name);

  friend class IEvent;
};
} // namespace tob::ebpf
