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

#include <tob/error/error.h>

namespace tob::ebpf {
class IPerfEvent {
public:
  using Ref = std::unique_ptr<IPerfEvent>;

  enum class Type {
    Kprobe,
    Kretprobe,

    Uprobe,
    Uretprobe,

    Tracepoint
  };

  static StringErrorOr<Ref> createTracepoint(const std::string &name,
                                             bool exit_event,
                                             std::int32_t process_id = -1);

  static StringErrorOr<Ref> createKprobe(const std::string &name,
                                         bool ret_probe,
                                         std::int32_t process_id = -1);

  static StringErrorOr<Ref> createUprobe(const std::string &name,
                                         const std::string &path,
                                         bool ret_probe,
                                         std::int32_t process_id = -1);

  IPerfEvent() = default;
  virtual ~IPerfEvent() = default;

  virtual Type type() const = 0;
  virtual int fd() const = 0;

  IPerfEvent(const IPerfEvent &) = delete;
  IPerfEvent &operator=(const IPerfEvent &) = delete;
};
} // namespace tob::ebpf
