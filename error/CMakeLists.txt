#
# Copyright (c) 2019-present, Trail of Bits, Inc.
# All rights reserved.
#
# This source code is licensed in accordance with the terms specified in
# the LICENSE file found in the root directory of this source tree.
#

cmake_minimum_required(VERSION 3.16.3)
project("error")

function(ebpfCommonError)
  add_library(error INTERFACE)
  target_include_directories(error INTERFACE include)
  target_link_libraries(error INTERFACE cxx_target_settings)
endfunction()

ebpfCommonError()
