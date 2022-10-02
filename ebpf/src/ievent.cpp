/*
  Copyright (c) 2019-present, Trail of Bits, Inc.
  All rights reserved.

  This source code is licensed in accordance with the terms specified in
  the LICENSE file found in the root directory of this source tree.
*/

#include "kprobeevent.h"
#include "tracepointevent.h"
#include "uprobeevent.h"

#include <tob/ebpf/ievent.h>

namespace tob::ebpf {
StringErrorOr<IEvent::Ref> IEvent::createTracepoint(const std::string &category,
                                                    const std::string &name,
                                                    std::int32_t process_id) {

  try {
    return Ref(new TracepointEvent(category, name, process_id));

  } catch (const std::bad_alloc &) {
    return StringError::create("Memory allocation failure");

  } catch (const StringError &error) {
    return error;
  }
}

StringErrorOr<IEvent::Ref> IEvent::createKprobe(const std::string &name,
                                                bool ret_probe, bool is_syscall,
                                                std::int32_t process_id) {

  try {
    return Ref(new KprobeEvent(name, is_syscall, ret_probe, process_id));

  } catch (const std::bad_alloc &) {
    return StringError::create("Memory allocation failure");

  } catch (const StringError &error) {
    return error;
  }
}

StringErrorOr<IEvent::Ref> IEvent::createUprobe(const std::string &name,
                                                const std::string &path,
                                                bool ret_probe,
                                                std::int32_t process_id) {
  try {
    return Ref(new UprobeEvent(name, path, ret_probe, process_id));

  } catch (const std::bad_alloc &) {
    return StringError::create("Memory allocation failure");

  } catch (const StringError &error) {
    return error;
  }
}
} // namespace tob::ebpf
