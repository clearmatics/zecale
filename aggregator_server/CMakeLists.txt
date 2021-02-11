find_package(Protobuf REQUIRED)
find_package(gRPC REQUIRED)

# Add the directory containing the Protobuf and gRPC generated files.
# `PROTO_SRC_DIR` is defined in the parent CMakeLists.txt
include_directories(SYSTEM ${PROTO_SRC_DIR})

# Generate the gRPC files, and set the result of the generation in the
# given env var (GRPC_SRCS, GRPC_HDRS)
grpc_generate_cpp(GRPC_SRCS GRPC_HDRS ${PROTO_SRC_DIR} ${PROTO_FILES})

set_property(SOURCE ${GRPC_SRCS} PROPERTY
  COMPILE_FLAGS "-Wno-unused-variable -Wno-unused-parameter"
)

# Enable Boost for program_options
find_package(Boost REQUIRED COMPONENTS system filesystem program_options)
include_directories(SYSTEM ${Boost_INCLUDE_DIR})

# Add the binary tree to the search path for include files
# so that we will find zecale_config.h
include_directories(${PROJECT_BINARY_DIR})

# aggregator_server executable
file(
  GLOB_RECURSE
  AGGREGATOR_SERVER_SOURCE
  aggregator_server.cpp
)
add_executable(
  aggregator_server
  ${AGGREGATOR_SERVER_SOURCE}
  ${GRPC_SRCS}
)

if (NOT APPLE)
  find_package(PkgConfig REQUIRED)
  pkg_check_modules(GRPC REQUIRED IMPORTED_TARGET grpc++)
endif()

target_link_libraries(
  aggregator_server

  zecale
  ${Boost_SYSTEM_LIBRARY}
  ${Boost_FILESYSTEM_LIBRARY}
  ${Boost_PROGRAM_OPTIONS_LIBRARY}
  ${GRPC_LIBRARIES}
  gRPC::grpc++_reflection
  protobuf::libprotobuf
)
