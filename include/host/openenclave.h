#ifndef _HOST_OPENENCLAVE_H
#define _HOST_OPENENCLAVE_H

#include <stddef.h>
#include <string.h>
#include <stdlib.h>
#include <stdio.h>
#include <stdint.h>
#include <stdarg.h>
#include "openenclave/defs.h"
#include "openenclave/types.h"
#include "openenclave/result.h"
#include "openenclave/thread.h"
#include "openenclave/sha.h"
#include "openenclave/typeinfo.h"
#include "openenclave/atomic.h"

OE_EXTERNC_BEGIN

#ifdef __cplusplus
# define OE_OCALL OE_EXTERNC OE_EXPORT
#else
# define OE_OCALL OE_EXPORT
#endif

typedef struct _OE_Enclave OE_Enclave;

#define OE_FLAG_DEBUG 1
#define OE_FLAG_SIMULATE 2

OE_Result OE_CreateEnclave(
    const char* path,
    uint32_t flags,
    OE_Enclave** enclave);

OE_Result OE_TerminateEnclave(
    OE_Enclave* enclave);

OE_Result OE_CallEnclave(
    OE_Enclave* enclave,
    const char* func,
    void* args);

OE_Result OE_GetQuote(
    const void* report,
    size_t reportSize,
    void* quote,
    size_t* quoteSize);

OE_Result __OE_ECall(
    OE_Enclave* enclave,
    int func,
    uint64_t argIn,
    uint64_t* argOut);

OE_PRINTF_FORMAT(3, 4)
void __OE_PutErr(
    const char* file,
    unsigned int line,
    const char* format, 
    ...);

void OE_SetProgramName(
    const char* name);

#define OE_PutErr(...) __OE_PutErr(__FILE__, __LINE__, __VA_ARGS__)

OE_EXTERNC_END

#endif /* _HOST_OPENENCLAVE_H */