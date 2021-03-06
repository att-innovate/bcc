# Copyright (c) PLUMgrid, Inc.
# Licensed under the Apache License, Version 2.0 (the "License")

include_directories(${CMAKE_CURRENT_BINARY_DIR})
include_directories(${CMAKE_CURRENT_SOURCE_DIR})
# to be removed
include_directories(${CMAKE_CURRENT_BINARY_DIR}/frontends/b)
include_directories(${CMAKE_CURRENT_SOURCE_DIR}/frontends/b)
include_directories(${CMAKE_CURRENT_SOURCE_DIR}/frontends/clang)
include_directories(${LLVM_INCLUDE_DIRS})
# todo: if check for kernel version
include_directories(${CMAKE_CURRENT_SOURCE_DIR}/compat)
add_definitions(${LLVM_DEFINITIONS})
configure_file(libbcc.pc.in ${CMAKE_CURRENT_BINARY_DIR}/libbcc.pc @ONLY)

# prune unused llvm static library stuff when linking into the new .so
set(CMAKE_SHARED_LINKER_FLAGS "${CMAKE_SHARED_LINKER_FLAGS} -Wl,--exclude-libs=ALL")
set(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} -fPIC")
set(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} -fPIC")

# if gcc 4.9 or higher is used, static libstdc++ is a good option
if (CMAKE_COMPILER_IS_GNUCC)
  execute_process(COMMAND ${CMAKE_C_COMPILER} -dumpversion OUTPUT_VARIABLE GCC_VERSION)
  if (GCC_VERSION VERSION_GREATER 4.9 OR GCC_VERSION VERSION_EQUAL 4.9)
    execute_process(COMMAND ${CMAKE_C_COMPILER} -print-libgcc-file-name OUTPUT_VARIABLE GCC_LIB)
    get_filename_component(GCC_DIR "${GCC_LIB}" DIRECTORY)
    find_library(GCC_LIBSTDCPP libstdc++.a PATHS "${GCC_DIR}" NO_DEFAULT_PATH)
    if (GCC_LIBSTDCPP)
      message(STATUS "Using static-libstdc++")
      set(CMAKE_SHARED_LINKER_FLAGS "${CMAKE_SHARED_LINKER_FLAGS} -static-libstdc++")
    endif()
  endif()
endif()

add_library(bcc-shared SHARED bpf_common.cc bpf_module.cc libbpf.c perf_reader.c shared_table.cc exported_files.cc)
set_target_properties(bcc-shared PROPERTIES VERSION ${REVISION_LAST} SOVERSION 0)
set_target_properties(bcc-shared PROPERTIES OUTPUT_NAME bcc)

add_library(bcc-loader-static libbpf.c perf_reader.c)
add_library(bcc-static STATIC bpf_common.cc bpf_module.cc shared_table.cc exported_files.cc)
set_target_properties(bcc-static PROPERTIES OUTPUT_NAME bcc)

# BPF is still experimental otherwise it should be available
#llvm_map_components_to_libnames(llvm_libs bpf mcjit irreader passes)
llvm_map_components_to_libnames(llvm_libs bitwriter bpfcodegen irreader linker
  mcjit objcarcopts option passes x86codegen)
llvm_expand_dependencies(expanded_libs ${llvm_libs})

# order is important
set(clang_libs ${libclangFrontend} ${libclangSerialization} ${libclangDriver} ${libclangParse}
  ${libclangSema} ${libclangCodeGen} ${libclangAnalysis} ${libclangRewrite} ${libclangEdit}
  ${libclangAST} ${libclangLex} ${libclangBasic})

# Link against LLVM libraries
target_link_libraries(bcc-shared b_frontend clang_frontend ${clang_libs} ${expanded_libs})
target_link_libraries(bcc-static b_frontend clang_frontend bcc-loader-static ${clang_libs} ${expanded_libs})

install(TARGETS bcc-shared LIBRARY COMPONENT libbcc
  DESTINATION ${CMAKE_INSTALL_LIBDIR})
install(FILES bpf_common.h bpf_module.h ../libbpf.h COMPONENT libbcc
  DESTINATION include/bcc)
install(DIRECTORY compat/linux/ COMPONENT libbcc
  DESTINATION include/bcc/compat/linux
  FILES_MATCHING PATTERN "*.h")
install(FILES ${CMAKE_CURRENT_BINARY_DIR}/libbcc.pc COMPONENT libbcc
  DESTINATION ${CMAKE_INSTALL_LIBDIR}/pkgconfig)

add_subdirectory(frontends)
