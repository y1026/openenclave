# Copyright (c) Microsoft Corporation. All rights reserved.
# Licensed under the MIT License.

add_subdirectory(host)

if (UNIX)
    add_subdirectory(enc)
endif()

add_enclave_test(tests/bigmalloc ./host bigmalloc_host ./enc bigmalloc_enc.signed.so)
set_tests_properties(tests/bigmalloc PROPERTIES SKIP_RETURN_CODE 2)
