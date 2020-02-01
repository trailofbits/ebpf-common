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
class UprobePerfEvent final : public IPerfEvent {
  struct PrivateData;
  std::unique_ptr<PrivateData> d;

public:
  virtual ~UprobePerfEvent() override;

  virtual Type type() const override;

  virtual const std::string &name() const override;
  virtual std::uint32_t identifier() const override;
  virtual int fd() const override;

protected:
  UprobePerfEvent(const std::string &name, const std::string &path,
                  bool ret_probe, std::uint32_t identifier,
                  std::int32_t process_id);

  friend class IPerfEvent;
};
} // namespace tob::ebpf
