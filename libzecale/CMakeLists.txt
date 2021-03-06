include_directories(.)

find_package(Protobuf REQUIRED)
find_package(gRPC REQUIRED)

include_directories(SYSTEM ${PROTO_SRC_DIR})

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

# zecale library
file(
  GLOB_RECURSE
  ZECALE_SOURCE
  *.hpp
  circuits/**.?pp circuits/**.tcc
  core/**.?pp core/**.tcc
  serialization/**.?pp serialization/**.tcc
)
add_library(
  zecale
  ${ZECALE_SOURCE}
  ${PROTO_SRCS}
)

target_include_directories(
  zecale

  SYSTEM
  PUBLIC
  ${DEPENDS_DIR}/zeth
  ${DEPENDS_DIR}/zeth/depends/libsnark
  ${DEPENDS_DIR}/zeth/depends/libsnark/depends/libff
  ${DEPENDS_DIR}/zeth/depends/libsnark/depends/libfqfft
  ${PROJECT_BINARY_DIR}/depends/zeth
)
target_link_libraries(
  zecale
  zeth
)

add_subdirectory(tests)
