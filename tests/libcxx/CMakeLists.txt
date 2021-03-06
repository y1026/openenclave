# Copyright (c) Microsoft Corporation. All rights reserved.
# Licensed under the MIT License.

# add a test-case for each file listed in tests.supported
include(${CMAKE_CURRENT_LIST_DIR}/../../cmake/get_testcase_name.cmake)

# read tests.supported, sanitize the cpp-file, and create the test-case
if (ENABLE_FULL_LIBCXX_TESTS)
    file(STRINGS "tests.supported" alltests)
else()
    file(STRINGS "tests.supported.default" alltests)
endif()

add_subdirectory(host)

if (UNIX)
	add_subdirectory(enc)
endif()

foreach(testcase ${alltests})
    get_testcase_name(${testcase} name "../../3rdparty/libcxx/libcxx/test/")

# the allocations are entirely optimized out by Clang in these tests and are excluded from Clang release builds
    if ("${name}" MATCHES "cons_default_throws_bad_alloc.pass" OR "${name}" MATCHES "allocator_allocator.members_construct.pass")
        string(TOUPPER ${CMAKE_BUILD_TYPE} BUILD_TYPE_UPPER)
        if (CMAKE_CXX_COMPILER_ID MATCHES Clang AND BUILD_TYPE_UPPER MATCHES REL)
            continue()
        endif()
    endif()

    add_enclave_test(tests/libcxxtest-${name} ./host libcxx_host ./enc libcxxtest-${name}_enc)
endforeach(testcase)
