#
# Copyright (c) 2019-present, Trail of Bits, Inc.
# All rights reserved.
#
# This source code is licensed in accordance with the terms specified in
# the LICENSE file found in the root directory of this source tree.
#

add_library(thirdparty_libbpf INTERFACE)
target_include_directories(thirdparty_libbpf SYSTEM INTERFACE
  "${CMAKE_CURRENT_SOURCE_DIR}/src/include/uapi"
)
