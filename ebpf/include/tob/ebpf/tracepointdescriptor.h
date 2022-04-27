/*
  Copyright (c) 2019-present, Trail of Bits, Inc.
  All rights reserved.

  This source code is licensed in accordance with the terms specified in
  the LICENSE file found in the root directory of this source tree.
*/

#pragma once

#include <memory>
#include <unordered_map>
#include <vector>

#include <tob/ebpf/structure.h>
#include <tob/error/stringerror.h>

namespace tob::ebpf {
class TracepointDescriptor final {
public:
  enum class PathType { Root, Format, EventIdentifier };
  using PathMap = std::unordered_map<PathType, std::string>;

  using Ref = std::shared_ptr<TracepointDescriptor>;

  static StringErrorOr<Ref> create(const std::string &category,
                                   const std::string &name);

  ~TracepointDescriptor();

  const std::string &category() const;
  const std::string &name() const;

  StringErrorOr<std::string> path(const PathType &path_type) const;

  std::uint32_t eventIdentifier() const;

  const Structure &structure() const;

  TracepointDescriptor(const TracepointDescriptor &) = delete;
  TracepointDescriptor &operator=(const TracepointDescriptor &) = delete;

protected:
  TracepointDescriptor(const std::string &category, const std::string &name);

private:
  struct PrivateData;
  std::unique_ptr<PrivateData> d;

public:
  static PathMap getTracepointPathMap(const std::string &category,
                                      const std::string &name);

  static StringErrorOr<std::string> readFile(const std::string &path);

  static StringErrorOr<StructureField>
  parseTracepointDescriptorFormatLine(const std::string &format_line);

  static StringErrorOr<Structure>
  parseTracepointDescriptorFormat(const std::string &format);

  static std::string normalizeStructureFieldType(const std::string &type);
};
} // namespace tob::ebpf
