/*
  Copyright (c) 2019-present, Trail of Bits, Inc.
  All rights reserved.

  This source code is licensed in accordance with the terms specified in
  the LICENSE file found in the root directory of this source tree.
*/

#pragma once

#include <cstdint>
#include <memory>
#include <vector>

#include <tob/error/stringerror.h>

namespace tob::utils {

class BufferReader final {
public:
  struct ReadError final {
    std::size_t offset{0U};
    std::size_t size{0U};
  };

  using Ptr = std::unique_ptr<BufferReader>;
  static StringErrorOr<Ptr> create();

  ~BufferReader();

  void reset(const std::uint8_t *buffer, std::size_t size);
  void reset(const std::vector<std::uint8_t> &buffer);

  std::size_t offset() const;
  void setOffset(std::size_t offset);
  void skipBytes(std::size_t byte_count);

  template <typename T> void read(T destination, std::size_t size);

  std::uint8_t u8();
  std::uint16_t u16();
  std::uint32_t u32();
  std::uint64_t u64();

  std::uint8_t peekU8(std::size_t offset);
  std::uint16_t peekU16(std::size_t offset);
  std::uint32_t peekU32(std::size_t offset);
  std::uint64_t peekU64(std::size_t offset);

  std::size_t bytesRead() const;
  std::size_t availableBytes() const;

  BufferReader(const BufferReader &) = delete;
  BufferReader &operator=(const BufferReader &) = delete;

private:
  struct PrivateData;
  std::unique_ptr<PrivateData> d;

  BufferReader();
};

} // namespace tob::utils
