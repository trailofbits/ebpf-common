/*
  Copyright (c) 2019-present, Trail of Bits, Inc.
  All rights reserved.

  This source code is licensed in accordance with the terms specified in
  the LICENSE file found in the root directory of this source tree.
*/

#include "kprobeperfevent.h"
#include "tracepointperfevent.h"
#include "uprobeperfevent.h"

#include <tob/ebpf/iperfevent.h>

namespace tob::ebpf {
StringErrorOr<IPerfEvent::Ref>
IPerfEvent::createTracepoint(const std::string &category,
                             const std::string &name, std::int32_t process_id) {

  try {
    return Ref(new TracepointPerfEvent(category, name, process_id));

  } catch (const std::bad_alloc &) {
    return StringError::create("Memory allocation failure");

  } catch (const StringError &error) {
    return error;
  }
}

StringErrorOr<IPerfEvent::Ref>
IPerfEvent::createKprobe(const std::string &name, bool ret_probe,
                         std::int32_t process_id) {

  try {
    return Ref(new KprobePerfEvent(name, ret_probe, process_id));

  } catch (const std::bad_alloc &) {
    return StringError::create("Memory allocation failure");

  } catch (const StringError &error) {
    return error;
  }
}

StringErrorOr<IPerfEvent::Ref>
IPerfEvent::createUprobe(const std::string &name, const std::string &path,
                         bool ret_probe, std::int32_t process_id) {
  try {
    return Ref(new UprobePerfEvent(name, path, ret_probe, process_id));

  } catch (const std::bad_alloc &) {
    return StringError::create("Memory allocation failure");

  } catch (const StringError &error) {
    return error;
  }
}
} // namespace tob::ebpf
