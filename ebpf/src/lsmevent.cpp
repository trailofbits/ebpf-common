/*
  Copyright (c) 2019-present, Trail of Bits, Inc.
  All rights reserved.

  This source code is licensed in accordance with the terms specified in
  the LICENSE file found in the root directory of this source tree.
*/

#include "lsmevent.h"

#include <tob/utils/uniquefd.h>

#include <btfparse/ibtf.h>

namespace tob::ebpf {
struct LSMEvent::PrivateData final {
  std::string name;
  std::uint32_t btf_func_type;
  utils::UniqueFd event{-1};
};

LSMEvent::~LSMEvent() {}

LSMEvent::Type LSMEvent::type() const { return Type::LSM; }

std::string LSMEvent::name() const { return d->name; }

void LSMEvent::setFileDescriptor(int fd) { d->event.reset(fd); }

int LSMEvent::fd() const { return d->event.get(); }

bool LSMEvent::isSyscallKprobe() const { return false; }

bool LSMEvent::usesKprobeIndirectPtRegs() const { return false; }

std::uint32_t LSMEvent::btfTypeID() const { return d->btf_func_type; }

LSMEvent::LSMEvent(const std::filesystem::path &btf_path,
                   const std::string &name)
    : d(new PrivateData) {

  auto btf_res = btfparse::IBTF::createFromPath(btf_path);
  if (btf_res.failed()) {
    throw StringError::create("Failed to open the following BTF file: " +
                              btf_path.string());
  }

  auto btf = btf_res.takeValue();

  std::uint32_t btf_func_id{};
  for (const auto &p : btf->getAll()) {
    const auto &id = p.first;
    if (btf->getKind(id) != btfparse::BTFKind::Func) {
      continue;
    }

    const auto &btf_type = p.second;

    const auto &func_btf_kind = std::get<btfparse::FuncBTFType>(btf_type);
    if (func_btf_kind.name == name) {
      btf_func_id = id;
      break;
    }
  }

  if (btf_func_id == 0) {
    throw StringError::create("Invalid LSM event: " + name);
  }

  d->btf_func_type = btf_func_id;
  d->name = name;
}
} // namespace tob::ebpf
