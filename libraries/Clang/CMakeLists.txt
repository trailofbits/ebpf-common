#
# Copyright (c) 2019-present, Trail of Bits, Inc.
# All rights reserved.
#
# This source code is licensed in accordance with the terms specified in
# the LICENSE file found in the root directory of this source tree.
#

set(clang_library_name_list
  clangParse
  clangRewrite
  clangRewriteFrontend
  
  clangAST
  clangFrontend
  clangBasic
  clangDriver
  clangLex
  clangSerialization
  clangAnalysis
  clangASTMatchers
  clangEdit
  clangSema
  clangCodeGen
)

foreach(clang_library_name ${clang_library_name_list})
  set(variable_name "${clang_library_name}_path")

  find_library("${variable_name}"
    "lib${clang_library_name}.a"
    REQUIRED
  )

  list(APPEND clang_library_path_list
    "${${variable_name}}"
  )
endforeach()

add_library("thirdparty_clang" INTERFACE)
target_link_libraries("thirdparty_clang" INTERFACE
  ${clang_library_path_list}
)

target_include_directories("thirdparty_clang" SYSTEM INTERFACE
  ${CLANG_INCLUDE_DIRS}
)

target_link_libraries("thirdparty_clang" INTERFACE
  "external::llvm"
)

add_library("external::clang" ALIAS "thirdparty_clang")
