cmake_minimum_required(VERSION 3.15)

# Change the compiler BEFORE the first `project()` command to avoid an infinite loop.
# See: https://public.kitware.com/pipermail/cmake/2009-November/033133.html
if(APPLE)
  # If custom llvm compilers are available, use them (for openmp
  # support), otherwise disable multicore.
  if(EXISTS "/usr/local/opt/llvm/bin/clang")
    set(CMAKE_C_COMPILER "/usr/local/opt/llvm/bin/clang")
    set(CMAKE_CXX_COMPILER "/usr/local/opt/llvm/bin/clang++")
  endif()
endif()

# Sets the env vars PROJECT_SOURCE_DIR, and PROJECT_BINARY_DIR
project(zecale CXX)

# Versionning of the project
set (ZECALE_VERSION_MAJOR 0)
set (ZECALE_VERSION_MINOR 2)

set(CMAKE_CXX_STANDARD 11)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_CXX_EXTENSIONS OFF)

# Flags and compilation options to chose the type of zksnark
# TODO: Allow Zeth and Zecale to use different snarks. To do so, introduce
# separate variables in the cmake config
# Introduce the variables:
# - WSNARK, and NSNARK to match the template names
# - WCURVE, and NCURVE
set(
  ZECALE_SNARK
  "GROTH16"
  CACHE
  STRING
  "Default snark: one of PGHR13, GROTH16"
)

# Run only fast test (e.g. on CI machine)
option(
  FAST_TESTS_ONLY
  "Include only fast-running tests"
  OFF
)

# Flags and compilation options for use with libsnark
#
# Note: This configuration determines over which curve the zeth proofs are verifier/aggregated
# Here the Zeth proofs are assumed to be generated over MNT4 since we will verify them over MNT6
set(
  ZECALE_CURVE
  "BW6_761"
  CACHE
  STRING
  "Default curve (Warning: make sure the choosen curve matches the curve used to
  generate the nested proofs): one of MNT6, BW6_761"
)

# Configure a header file to pass some of the CMake settings
# to the source code
configure_file (
    "${PROJECT_SOURCE_DIR}/zecale_config.h.in"
    "${PROJECT_BINARY_DIR}/zecale_config.h"
)

# Dependencies
set(
  DEPENDS_DIR
  "${CMAKE_CURRENT_SOURCE_DIR}/depends"
)

set(
  OPT_FLAGS
  ""
  CACHE
  STRING
  "Override C++ compiler optimization flags"
)

option(
  MULTICORE
  "Enable parallelized execution, using OpenMP"
  ON
)

option(
  WITH_PROCPS
  "Use procps for memory profiling"
  ON
)

option(
  VERBOSE
  "Print internal messages"
  ON
)

option(
  DEBUG
  "Enable debugging mode"
  ON
)

option(
  BINARY_OUTPUT
  "Binary stream reading and writing"
  ON
)

option(
  MONTGOMERY_OUTPUT
  "Serialize Fp elements as their Montgomery representations (faster but not human-readable)"
  ON
)

option(
  USE_PT_COMPRESSION
  "Use point compression"
  OFF
)

option(
  GEN_DOC
  "Generate project documentation"
  OFF
)

option(
  CODE_COVERAGE
  "Generate code coverage report"
  OFF
)

if(APPLE)
  # These must be disabled to make dependencies build on macos
  set(WITH_PROCPS OFF)
  set(WITH_SUPERCOP OFF CACHE BOOL "Build libff with supercop")

  # (Currently) OpenMP only available with custom llvm compilers
  if(${CMAKE_C_COMPILER} MATCHES ".*cc$")
    set(MULTICORE OFF)
  endif()
endif()

if(CMAKE_COMPILER_IS_GNUCXX OR "${CMAKE_CXX_COMPILER_ID}" MATCHES "^(Apple)?Clang$")

  # Common compilation flags and warning configuration
  # The CMAKE_CXX_FLAGS variable allows to change the compiler settings
  set(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} -std=c++11 -Wall -Wextra -Wfatal-errors -pthread")

  if("${MULTICORE}")
    set(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} -fopenmp")
  endif()

   # Default optimizations flags (to override, use -DOPT_FLAGS=...)
  if("${OPT_FLAGS}" STREQUAL "")
    set(OPT_FLAGS "-ggdb3 -O2 -march=native -mtune=native")
  endif()
endif()

enable_testing()

if("${VERBOSE}")
  add_definitions(-DVERBOSE=1)
endif()

if("${MULTICORE}")
  add_definitions(-DMULTICORE=1)
endif()

if("${BINARY_OUTPUT}")
  add_definitions(-DBINARY_OUTPUT)
endif()

if("${MONTGOMERY_OUTPUT}")
  add_definitions(-DMONTGOMERY_OUTPUT)
endif()

if(NOT "${USE_PT_COMPRESSION}")
  add_definitions(-DNO_PT_COMPRESSION=1)
endif()

if("${DEBUG}")
  add_definitions(-DDEBUG=1)
endif()

# Add the given directories to those the compiler uses to search for include files
include_directories(.)

add_custom_target(check COMMAND ${CMAKE_CTEST_COMMAND})

# Add dependencies
add_subdirectory(depends)

# CMAKE_MODULE_PATH: Path used for searching by FIND_XXX(), with appropriate
# suffixes added.
# See: https://cmake.org/cmake/help/v3.0/variable/CMAKE_PREFIX_PATH.html
list(APPEND CMAKE_PREFIX_PATH "/usr/local/lib" "/usr/lib")
# Cmake find modules
list(APPEND CMAKE_MODULE_PATH "${PROJECT_SOURCE_DIR}/cmake")

# Set the target of the Protobuf and gRPC generated files.
set(
  PROTO_SRC_DIR
  ${PROJECT_BINARY_DIR}
)

# Get the proto files
file(
  GLOB
  PROTO_FILES
  ${PROJECT_SOURCE_DIR}/proto/zecale/api/*.proto
)

# Set the import path to be able to re-use the Zeth proto files
set(PROTOBUF_IMPORT_DIRS ${PROJECT_SOURCE_DIR}/depends/zeth/proto)

set(PROTOBUF_PROTO_PATH ${PROJECT_SOURCE_DIR}/proto)
set(PROTOBUF_APPEND_DEST_PATH "/zecale/api")
set(PROTOBUF_GENERATE_CPP_APPEND_PATH OFF)
set(GRPC_GENERATE_CPP_APPEND_PATH OFF)

# By default, compile with all warning flags
add_compile_options(-Wall -Wextra)

# Add extra configuration files to run additional tooling on the code and to
# generate documentation and code coverage reports
#
# Import configuration to run dev tools on the code
# Generate the compile database needed for some of the tools we invoke below
set(CMAKE_EXPORT_COMPILE_COMMANDS ON)
include(cmake/gcc_dev_tools.cmake)
include(cmake/clang_dev_tools.cmake)

# Import configuration to compile targets with sanitizers
include(cmake/sanitizers.cmake)

# Import configuration to generate the code documentation if option is set
if("${GEN_DOC}")
    include(cmake/documentation.cmake)
endif()

# Import configuration to generate the coverage report if option is set
if("${CODE_COVERAGE}")
    include(cmake/code_coverage.cmake)
endif()

# Add all local subdirecetories
add_subdirectory(libzecale)
add_subdirectory(aggregator_server)
