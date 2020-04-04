#
# Copyright (c) 2019-present, Trail of Bits, Inc.
# All rights reserved.
#
# This source code is licensed in accordance with the terms specified in
# the LICENSE file found in the root directory of this source tree.
#

cmake_minimum_required(VERSION 3.14.6)
project("utils")

function(ebpfCommonUtils)
  add_library(utils OBJECT
    include/tob/utils/uniqueref.h

    include/tob/utils/uniquefd.h
    src/uniquefd.cpp

    include/tob/utils/uniquemappedmemory.h
    src/uniquemappedmemory.cpp

    include/tob/utils/ielfimage.h
    src/elfimage.h
    src/elfimage.cpp
  )

  target_include_directories(utils PUBLIC include)
  target_link_libraries(utils PUBLIC error)
endfunction()

ebpfCommonUtils()
