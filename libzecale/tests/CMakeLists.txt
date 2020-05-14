## Tests

include(CTest)

# A target which builds all tests, even if they will not be run.
add_custom_target(build_tests)

# Function to create test targets, based on the FAST flag:
#
#   zecale_test(
#     <test name> SOURCE <source files> [ARGS <tst arguments>] [FAST])
function(zecale_test TEST_NAME)
  cmake_parse_arguments(zecale_test "FAST" "" "SOURCE;ARGS" ${ARGN})
  file(GLOB test_src ${zecale_test_SOURCE})

  message("TEST: ${TEST_NAME} ${zecale_test_SOURCE} (${zecale_test_FAST})")

  # Test executable
  add_executable(${TEST_NAME} EXCLUDE_FROM_ALL ${test_src})
  target_link_libraries(
    ${TEST_NAME}

    zecale
    gtest_main
    ${Boost_SYSTEM_LIBRARY}
    ${Boost_FILESYSTEM_LIBRARY}
    protobuf::libprotobuf
  )

  # Add all tests to the 'build_tests' target
  add_dependencies(build_tests ${TEST_NAME})

  if((NOT FAST_TESTS_ONLY) OR zecale_test_FAST)
    add_test(NAME ${TEST_NAME} COMMAND ${TEST_NAME} ${zecale_test_ARGS})
    add_dependencies(check ${TEST_NAME})
  else()
    message("Skipping slow test ${TEST_NAME}")
  endif()
endfunction(zecale_test)

# Function to process a list of test files, generating test names:
#
#   zecale_tests(SOURCES <sources> [ARGS <args>] [FAST])
function(zecale_tests)
  unset(fast)
  cmake_parse_arguments(zecale_tests "FAST" "" "SOURCES;ARGS" ${ARGN})
  if(zecale_tests_FAST)
    set(fast FAST)
  endif()
  foreach(TEST_SOURCE ${zecale_tests_SOURCES})
    get_filename_component(TEST_NAME ${TEST_SOURCE} NAME_WE)
    zecale_test(
      ${TEST_NAME}
      SOURCE ${TEST_SOURCE}
      ARGS "${zecale_tests_ARGS}"
      ${fast}
    )
  endforeach()
endfunction(zecale_tests)

# Most tests are considered FAST
file(
  GLOB_RECURSE
  TEST_SOURCE_FILES
  core/**_test.cpp
  circuits/**_test.cpp
  serialization/**_test.cpp
)
zecale_tests(SOURCES ${TEST_SOURCE_FILES} ARGS "${CMAKE_CURRENT_LIST_DIR}/../.." FAST)

# `aggregator` tests are considered SLOW
file(GLOB_RECURSE TEST_SOURCE_FILES aggregator/**_test.cpp)
zecale_tests(SOURCES ${TEST_SOURCE_FILES} ARGS "${CMAKE_CURRENT_LIST_DIR}/../..")
