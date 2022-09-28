#
# Copyright (c) 2019-present, Trail of Bits, Inc.
# All rights reserved.
#
# This source code is licensed in accordance with the terms specified in
# the LICENSE file found in the root directory of this source tree.
#

find_package(LLVM REQUIRED CONFIG)

set(EBPF_COMMON_ZLIB_LIBRARY_PATH "" CACHE FILEPATH "Specifies the path of the zlib library file to use. If left empty the system one will be used")

set(llvm_component_list
  "core"
  "bpfcodegen"
  "executionengine"
  "mcjit"
  "passes"
  "option"
  "coverage"
  "lto"
  "coroutines"
)

if("${CMAKE_SYSTEM_PROCESSOR}" STREQUAL "x86_64")
  list(APPEND llvm_component_list x86codegen)

elseif("${CMAKE_SYSTEM_PROCESSOR}" STREQUAL "aarch64")
  list(APPEND llvm_component_list aarch64codegen)

else()
  message(FATAL_ERROR "Unsupported architecture: ${CMAKE_SYSTEM_PROCESSOR}")
endif()

llvm_map_components_to_libnames(llvm_library_list
  ${llvm_component_list}
)

if(NOT "${EBPF_COMMON_ZLIB_LIBRARY_PATH}" STREQUAL "")
  # This is a bit of a hack. The LLVM libraries want to link against a shared version of libz,
  # some ebpfpub users want to be able to override this, to avoid using the system one.
  # We therefore list all the library targets that the user of ebpf-common will end up linking,
  # and remove any reference to "z" or "-lz" and use the one specified in EBPF_COMMON_ZLIB_LIBRARY
  message(STATUS "ebpf-common - Overriding zlib library with: ${EBPF_COMMON_ZLIB_LIBRARY_PATH}")

  # This is an LLVM CMake helper function which lists all the library targets that the user will end up linking against
  explicit_map_components_to_libraries(llvm_full_library_list ${llvm_component_list})

  foreach(llvm_library ${llvm_full_library_list})
    get_target_property(interface_link_options ${llvm_library} INTERFACE_LINK_OPTIONS)
    get_target_property(interface_link_libraries ${llvm_library} INTERFACE_LINK_LIBRARIES)

    if(NOT "${interface_link_options}" STREQUAL "interface_link_options-NOTFOUND")
      list(FIND interface_link_options "-lz" libz_pos)

      if (NOT ${libz_pos} EQUAL -1)
        list(REMOVE_ITEM interface_link_options "-lz")
        set_target_properties(${llvm_library} PROPERTIES INTERFACE_LINK_OPTIONS ${interface_link_options})
      endif()
    endif()

    if(NOT "${interface_link_libraries}" STREQUAL "interface_link_libraries-NOTFOUND")
      set(substitute_zlib FALSE)

      list(FIND interface_link_libraries "z" libz_pos)

      if (NOT ${libz_pos} EQUAL -1)
        set(substitute_zlib TRUE)
        list(REMOVE_ITEM interface_link_libraries "z")
      endif()

      list(FIND interface_link_libraries "-lz" libz_pos)

      if (NOT ${libz_pos} EQUAL -1)
        set(substitute_zlib TRUE)
        list(REMOVE_ITEM interface_link_libraries "-lz")
      endif()

      if(substitute_zlib)
        list(APPEND interface_link_libraries "${EBPF_COMMON_ZLIB_LIBRARY_PATH}")
        set_target_properties(${llvm_library} PROPERTIES INTERFACE_LINK_LIBRARIES "${interface_link_libraries}")
      endif()
    endif()
  endforeach()
endif()

add_library("thirdparty_llvm" INTERFACE)
target_link_libraries("thirdparty_llvm" INTERFACE ${llvm_library_list})

target_include_directories("thirdparty_llvm" SYSTEM INTERFACE
  ${LLVM_INCLUDE_DIRS}
)

target_compile_definitions("thirdparty_llvm" INTERFACE
  ${LLVM_DEFINITIONS}
  LLVM_VERSION_MAJOR=${LLVM_VERSION_MAJOR}
  LLVM_VERSION_MINOR=${LLVM_VERSION_MINOR}
)

add_library("external::llvm" ALIAS "thirdparty_llvm")
