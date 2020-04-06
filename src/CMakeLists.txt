include_directories(.)

# GRPC and Protocol Buffers libraries location
# `ldconfig -p | grep libgrpc`
# `ldconfig -p | grep libprotobuf`
# Returns the location of the GRPC and Protocol Buffers libraries
#
# CMAKE_MODULE_PATH: Path used for searching by FIND_XXX(), with appropriate suffixes added.
# See: https://cmake.org/cmake/help/v3.0/variable/CMAKE_PREFIX_PATH.html
list(APPEND CMAKE_PREFIX_PATH "/usr/local/lib" "/usr/lib")

# Cmake find modules
list(APPEND CMAKE_MODULE_PATH "${CMAKE_CURRENT_LIST_DIR}/cmake")

find_package(Protobuf REQUIRED)
find_package(GRPC REQUIRED)

file(
  GLOB
  PROTO_FILES
  ${PROJECT_SOURCE_DIR}/api/*.proto
)

# Set the target of the generated files to ${CMAKE_CURRENT_BINARY_DIR}/proto-src
# Then create this folder and add it to the include directories
set(PROTO_SRC_DIR ${CMAKE_CURRENT_BINARY_DIR}/proto_src)
file(MAKE_DIRECTORY ${PROTO_SRC_DIR})
include_directories(${PROTO_SRC_DIR})

set(PROTOBUF_IMPORT_DIRS ${PROJECT_SOURCE_DIR})
set(PROTOBUF_PROTO_PATH ${PROJECT_SOURCE_DIR})
set(PROTOBUF_APPEND_DEST_PATH "/api")
set(PROTOBUF_GENERATE_CPP_APPEND_PATH FALSE)
set(GRPC_GENERATE_CPP_APPEND_PATH FALSE)

# See cmake scripts in the cmake folder
# Generate the grpc and protobuf files and set the result of the generation
# in the given env var (PROTO_SRCS, PROTO_HDRS, GRPC_SRCS, GRPC_HDRS)
protobuf_generate_cpp(PROTO_SRCS PROTO_HDRS ${PROTO_SRC_DIR} ${PROTO_FILES})
grpc_generate_cpp(GRPC_SRCS GRPC_HDRS ${PROTO_SRC_DIR} ${PROTO_FILES})

set_property(SOURCE ${PROTO_SRCS} PROPERTY
  COMPILE_FLAGS "-Wno-unused-variable -Wno-unused-parameter"
)
set_property(SOURCE ${GRPC_SRCS} PROPERTY
  COMPILE_FLAGS "-Wno-unused-variable -Wno-unused-parameter"
)

# Enable Boost for program_options
find_package( Boost REQUIRED COMPONENTS system filesystem program_options )
include_directories( ${Boost_INCLUDE_DIR} )

# Add the binary tree to the search path for include files
# so that we will find zecaleConfig.h
include_directories( ${PROJECT_BINARY_DIR} )

string(TOLOWER ${ZKSNARK} ZKSNARK_NAME)

# zecale library
file(
  GLOB_RECURSE
  ZECALE_SOURCE
  circuits/**.?pp circuits/**.tcc
  aggregator_circuit_wrapper.???
  util.?pp util.tcc
  zecale.h
)
add_library(zecale ${ZECALE_SOURCE} ${PROTO_SRCS})
target_include_directories(
  zecale

  PUBLIC
  ${DEPENDS_DIR}/zeth
  ${DEPENDS_DIR}/zeth/depends/libsnark
  ${DEPENDS_DIR}/zeth/depends/libsnark/depends/libff
  ${DEPENDS_DIR}/zeth/depends/libsnark/depends/libfqfft
)
target_link_libraries(zecale zeth)

# aggregator_server executable
file(
  GLOB_RECURSE
  AGGREGATOR_SERVER_SOURCE
  aggregator_server/*.?pp aggregator_server/*.tcc
)
add_executable(aggregator_server ${AGGREGATOR_SERVER_SOURCE} ${GRPC_SRCS})
target_link_libraries(
  aggregator_server

  zecale
  ${Boost_SYSTEM_LIBRARY}
  ${Boost_FILESYSTEM_LIBRARY}
  ${Boost_PROGRAM_OPTIONS_LIBRARY}
  gRPC::grpc++_reflection
  protobuf::libprotobuf
)

## Tests
include(CTest)

# A target which builds all tests, even if they will not be run.
add_custom_target(build_tests)

function(zecale_test TEST_NAME)
  cmake_parse_arguments(zecale_test "FAST" "" "SOURCE" ${ARGN} )
  file(GLOB test_src ${zecale_test_SOURCE})

  # Test executable
  add_executable(${TEST_NAME} EXCLUDE_FROM_ALL ${test_src})
  target_link_libraries(${TEST_NAME} zecale gtest_main ${Boost_SYSTEM_LIBRARY})

  # Add all tests to the 'build_tests' target
  add_dependencies(build_tests ${TEST_NAME})

  if((NOT FAST_TESTS_ONLY) OR zecale_test_FAST)
    add_test(NAME ${TEST_NAME} COMMAND ${TEST_NAME})
    add_dependencies(check ${TEST_NAME})
  else()
    message("Skipping slow test ${TEST_NAME}")
  endif()
endfunction(zecale_test)

zecale_test(util_test SOURCE test/util_test.cpp FAST)
zecale_test(application_pool_test SOURCE test/application_pool_test.cpp FAST)
zecale_test(pairing_circuits_test SOURCE test/pairing_circuits_test.cpp FAST)
zecale_test(groth16_verifier_circuit_test SOURCE test/groth16_verifier_circuit_test.cpp FAST)

zecale_test(util_api_test SOURCE test/util_api_test.cpp FAST)
target_link_libraries(
  util_api_test

  zecale
  ${Boost_SYSTEM_LIBRARY}
  ${Boost_FILESYSTEM_LIBRARY}
  gRPC::grpc++_reflection
  protobuf::libprotobuf
)

zecale_test(aggregator_test SOURCE test/aggregator_test.cpp FAST)
# aggregator test has extra dependencies
target_link_libraries(
  aggregator_test

  zecale
  ${Boost_SYSTEM_LIBRARY}
  ${Boost_FILESYSTEM_LIBRARY}
)