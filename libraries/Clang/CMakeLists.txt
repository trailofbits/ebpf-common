#
# Copyright (c) 2019-present, Trail of Bits, Inc.
# All rights reserved.
#
# This source code is licensed in accordance with the terms specified in
# the LICENSE file found in the root directory of this source tree.
#

add_library("thirdparty_clang" INTERFACE)
target_link_libraries("thirdparty_clang" INTERFACE
  clangParse
  clangRewrite
  clangRewriteFrontend
  clangCodeGen
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
)

target_include_directories("thirdparty_clang" SYSTEM INTERFACE
  ${CLANG_INCLUDE_DIRS}
)

target_link_libraries("thirdparty_clang" INTERFACE
  "external::llvm"
)

add_library("external::clang" ALIAS "thirdparty_clang")
