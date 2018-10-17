// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT License.

/**
 * @file host.h
 *
 * This file defines the internal functions and data-structures used by
 * oeedger8r generated code on the host side.
 * These internals are subject to change without notice.
 *
 */
#ifndef _OE_EDGER8R_HOST_H
#define _OE_EDGER8R_HOST_H

#ifdef _OE_EDGER8R_ENCLAVE_H
#error \
    "edger8r/enclave.h and edger8r/host.h must not be included in the same compilation unit."
#endif

#include <openenclave/bits/defs.h>
#include <openenclave/bits/result.h>
#include <openenclave/bits/types.h>

/**
 * The type of a function in ocall function table.
 */
typedef void (*oe_ocall_func_t)(void*);

/**
 * Perform a high-level enclave function call (ECALL).
 *
 * Call the enclave function that matches the given function-id.
 * The enclave function is expected to have the following signature:
 *
 *     void (*)(void* args);
 *
 * Note that the return value of this function only indicates the success of
 * the call and not of the underlying function. The ECALL implementation must
 * define its own error reporting scheme via the arguments or return value.
 *
 * @param function_id The id of the enclave function that will be called.
 * @param input_buffer Buffer containing inputs data.
 * @param input_buffer_size Size of the input data buffer.
 * @param output_buffer Buffer where the outputs of the host function are
 * written to.
 * @param output_buffer_size Size of the output buffer.
 * @param output_bytes_written Number of bytes written in the output buffer.
 *
 * @return OE_OK the call was successful.
 * @return OE_NOT_FOUND if the function_id does not correspond to a function.
 * @return OE_INVALID_PARAMETER a parameter is invalid.
 * @return OE_FAILURE the call failed.
 * @return OE_BUFFER_TOO_SMALL the input or output buffer was smaller than
 * expected.
 *
 */
oe_result_t oe_call_enclave_function(
    oe_enclave_t* enclave,
    uint32_t function_id,
    void* input_buffer,
    size_t input_buffer_size,
    void* output_buffer,
    size_t output_buffer_size,
    size_t* output_bytes_written);

/******************************************************************************/
/********* Macros and inline functions used by generated code *****************/
/******************************************************************************/

/**
 * Add a size value, rounding to sizeof(void*).
 */
OE_INLINE oe_result_t oe_add_size(size_t* total, size_t size)
{
    oe_result_t result = OE_FAILURE;
    size_t align = sizeof(void*);
    size_t sum = 0;

    // Round size to multiple of sizeof(void*)
    size_t rsize = ((size + align - 1) / align) * align;
    if (rsize < size)
    {
        result = OE_INTEGER_OVERFLOW;
        goto done;
    }

    // Add rounded-size and check for overlow.
    sum = *total + rsize;
    if (sum < *total)
    {
        result = OE_INTEGER_OVERFLOW;
        goto done;
    }

    *total = sum;
    result = OE_OK;

done:
    return result;
}

#define OE_ADD_SIZE(total, size)                \
    do                                          \
    {                                           \
        if (oe_add_size(&total, size) != OE_OK) \
        {                                       \
            _result = OE_INTEGER_OVERFLOW;      \
            goto done;                          \
        }                                       \
    } while (0)

/**
 * Copy an input parameter to input buffer.
 */
#define OE_WRITE_IN_PARAM(argname, size)                                   \
    if (argname)                                                           \
    {                                                                      \
        *(uint8_t**)&_args.argname = _input_buffer + _input_buffer_offset; \
        memcpy(_args.argname, argname, (size_t)(size));                    \
        OE_ADD_SIZE(_input_buffer_offset, (size_t)(size));                 \
    }

#define OE_WRITE_IN_OUT_PARAM OE_WRITE_IN_PARAM

/**
 * Read an output parameter from output buffer.
 */
#define OE_READ_OUT_PARAM(argname, size)                                      \
    if (argname)                                                              \
    {                                                                         \
        memcpy(                                                               \
            argname, _output_buffer + _output_buffer_offset, (size_t)(size)); \
        OE_ADD_SIZE(_output_buffer_offset, (size_t)(size));                   \
    }

#define OE_READ_IN_OUT_PARAM OE_READ_OUT_PARAM

#endif // _OE_EDGER8R_HOST_H
