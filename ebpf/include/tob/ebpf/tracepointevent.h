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

#include <tob/error/error.h>

namespace tob::ebpf {
class TracepointEvent final {
public:
  struct StructureField final {
    std::string type;
    std::string name;
    std::size_t offset{0U};
    std::size_t size{0U};
    bool is_signed{false};
  };

  using Structure = std::vector<StructureField>;

  enum class PathType { Root, EnableSwitch, Format, EventIdentifier };
  using PathMap = std::unordered_map<PathType, std::string>;

  using Ref = std::shared_ptr<TracepointEvent>;

  static StringErrorOr<Ref> create(const std::string &category,
                                   const std::string &name);

  ~TracepointEvent();

  const std::string &category() const;
  const std::string &name() const;

  StringErrorOr<std::string> path(const PathType &path_type) const;

  std::uint32_t eventIdentifier() const;

  const Structure &structure() const;

  bool enable();
  bool disable();

  TracepointEvent(const TracepointEvent &) = delete;
  TracepointEvent &operator=(const TracepointEvent &) = delete;

protected:
  TracepointEvent(const std::string &category, const std::string &name);

private:
  struct PrivateData;
  std::unique_ptr<PrivateData> d;

public:
  static PathMap getTracepointPathMap(const std::string &category,
                                      const std::string &name);

  static StringErrorOr<std::string> readFile(const std::string &path);

  static StringErrorOr<StructureField>
  parseTracepointEventFormatLine(const std::string &format_line);

  static StringErrorOr<Structure>
  parseTracepointEventFormat(const std::string &format);

  static std::string normalizeStructureFieldType(const std::string &type);
};
} // namespace tob::ebpf
