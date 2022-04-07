#
# Copyright (c) 2019-present, Trail of Bits, Inc.
# All rights reserved.
#
# This source code is licensed in accordance with the terms specified in
# the LICENSE file found in the root directory of this source tree.
#

cmake_minimum_required(VERSION 3.14.6)
project("LLVM")

function(ebpfCommonLibrariesLLVM)
  find_package(LLVM REQUIRED CONFIG)

  set(llvm_component_list
    core
    bpfcodegen
    executionengine
    mcjit
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

  if(NOT EBPF_COMMON_ZLIB_LIBRARY_PATH STREQUAL "")
    # This is a bit of a hack. The LLVM libraries want to link against a shared version of libz,
    # some ebpfpub users want to be able to override this, to avoid using the system one.
    # We therefore list all the library targets that the user of ebpf-common will end up linking,
    # and remove any reference to "z" or "-lz" and use the one specified in EBPF_COMMON_ZLIB_LIBRARY

    if(NOT EXISTS "${EBPF_COMMON_ZLIB_LIBRARY_PATH}")
      message(FATAL_ERROR "The path specified in EBPF_COMMON_ZLIB_LIBRARY_PATH does not exist")
    endif()

    # This is an LLVM CMake helper function which lists all the library targets that the user will end up linking against
    explicit_map_components_to_libraries(llvm_full_library_list ${llvm_component_list})

    foreach(llvm_library ${llvm_full_library_list})
      get_target_property(INTERFACE_LINK_OPTIONS ${llvm_library} INTERFACE_LINK_OPTIONS)
      get_target_property(INTERFACE_LINK_LIBRARIES ${llvm_library} INTERFACE_LINK_LIBRARIES)

      if(NOT "${INTERFACE_LINK_OPTIONS}" STREQUAL "INTERFACE_LINK_OPTIONS-NOTFOUND")
        list(REMOVE_ITEM INTERFACE_LINK_OPTIONS "-lz" ${INTERFACE_LINK_OPTIONS})
        set_target_properties(${llvm_library} PROPERTIES INTERFACE_LINK_OPTIONS ${INTERFACE_LINK_OPTIONS})
        message(STATUS "Library ${llvm_library} setting options: ${INTERFACE_LINK_OPTIONS}")
      endif()

      if(NOT "${INTERFACE_LINK_LIBRARIES}" STREQUAL "INTERFACE_LINK_LIBRARIES-NOTFOUND")
        message(STATUS "Library ${llvm_library} starting with: ${INTERFACE_LINK_LIBRARIES}")
        list(REMOVE_ITEM INTERFACE_LINK_LIBRARIES "z")
        list(REMOVE_ITEM INTERFACE_LINK_LIBRARIES "-lz")
        list(APPEND INTERFACE_LINK_LIBRARIES "${EBPF_COMMON_ZLIB_LIBRARY_PATH}")
        set_target_properties(${llvm_library} PROPERTIES INTERFACE_LINK_LIBRARIES "${INTERFACE_LINK_LIBRARIES}")
        message(STATUS "Library ${llvm_library} setting libraries: ${INTERFACE_LINK_LIBRARIES}")
      endif()

    endforeach()
  endif()

  add_library(thirdparty_llvm INTERFACE)
  target_link_libraries(thirdparty_llvm INTERFACE ${llvm_library_list})

  target_include_directories(thirdparty_llvm SYSTEM INTERFACE
    ${LLVM_INCLUDE_DIRS}
  )

  target_compile_definitions(thirdparty_llvm INTERFACE
    ${LLVM_DEFINITIONS}
    LLVM_VERSION_MAJOR=${LLVM_VERSION_MAJOR}
    LLVM_VERSION_MINOR=${LLVM_VERSION_MINOR}
  )

  # Ubuntu/Debian workaround
  if(EXISTS "/usr/include/llvm-${LLVM_VERSION_MAJOR}")
    target_include_directories(thirdparty_llvm SYSTEM INTERFACE
      "/usr/include/llvm-${LLVM_VERSION_MAJOR}"
    )
  endif()
endfunction()

ebpfCommonLibrariesLLVM()
