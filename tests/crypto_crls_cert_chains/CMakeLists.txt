# Copyright (c) Microsoft Corporation. All rights reserved.
# Licensed under the MIT License.

add_subdirectory(host)

if (UNIX)
	add_subdirectory(enc)
endif()

add_enclave_test(tests/crypto_crls_cert_chains ./host crypto-extra_host ./enc crypto-extra_enc)
