#include <openenclave.h>
#include <__openenclave/sgxtypes.h>
#include <__openenclave/calls.h>

OE_Result SGX_CreateReport(
    const SGX_TargetInfo* targetInfo,
    const SGX_ReportData* reportData,
    SGX_Report* report)
{
    OE_Result result = OE_UNEXPECTED;
    SGX_TargetInfo* ti = NULL;
    SGX_ReportData* rd = NULL;
    SGX_Report* r = NULL;

    /* Reject invalid parameters (reportData may be null) */
    if (!targetInfo || !report)
        OE_THROW(OE_INVALID_PARAMETER);

    /* Reject parameters that do not reside in enclave memory */
    {
        if (!OE_IsWithinEnclave(targetInfo, sizeof(SGX_TargetInfo)))
            OE_THROW(OE_FAILURE);

        if (!OE_IsWithinEnclave(reportData, sizeof(SGX_ReportData)))
            OE_THROW(OE_FAILURE);

        if (report && !OE_IsWithinEnclave(report, sizeof(SGX_Report)))
            OE_THROW(OE_FAILURE);
    }

    /* Align TARGET INFO on 512 byte boundary */
    {
        if (!(ti = (SGX_TargetInfo*)memalign(512, sizeof(SGX_TargetInfo))))
            OE_THROW(OE_OUT_OF_MEMORY);

        memcpy(ti, targetInfo, sizeof(SGX_TargetInfo));
    }

    /* Align REPORT DATA on 128 byte boundary (if not null) */
    if (reportData)
    {
        if (!(rd = (SGX_ReportData*)memalign(128, sizeof(SGX_ReportData))))
            OE_THROW(OE_OUT_OF_MEMORY);

        memcpy(rd, reportData, sizeof(SGX_ReportData));
    }

    /* Align REPORT on 512 byte boundary */
    {
        if (!(r = (SGX_Report*)memalign(512, sizeof(SGX_Report))))
            OE_THROW(OE_OUT_OF_MEMORY);

        memset(r, 0, sizeof(SGX_Report));
    }

    asm volatile("/* @before */\n\t");

    /* Invoke EREPORT instruction */
    asm volatile(
        "mov %0, %%rbx\n\t" /* target info */
        "mov %1, %%rcx\n\t" /* report data */
        "mov %2, %%rdx\n\t" /* report */
        "mov %3, %%rax\n\t" /* EREPORT */
        "ENCLU\n\t"
        :
        :
        "m"(ti),
        "m"(rd),
        "m"(r),
        "i"(ENCLU_EREPORT));

    asm volatile("/* @after */\n\t");

    /* Copy REPORT to caller's buffer */
    memcpy(report, r, sizeof(SGX_Report));

    result = OE_OK;

catch:

    if (ti)
    {
        memset(ti, 0, sizeof(SGX_TargetInfo));
        free(ti);
    }

    if (rd)
    {
        memset(rd, 0, sizeof(SGX_ReportData));
        free(rd);
    }

    if (r)
    {
        memset(r, 0, sizeof(SGX_Report));
        free(r);
    }

    return result;
}

OE_CHECK_SIZE(sizeof(OE_EnclaveReportData), sizeof(SGX_ReportData));

OE_Result OE_GetReportForRemoteAttestation(
    const OE_EnclaveReportData *reportData,
    void *report,
    size_t* reportSize)
{
    OE_Result result = OE_UNEXPECTED;
    OE_InitQuoteArgs* args = NULL;
    SGX_TargetInfo targetInfo;

    /* Check report size */
    {
        if (!reportSize)
            OE_THROW(OE_INVALID_PARAMETER);

        if (*reportSize < sizeof(SGX_Report))
        {
            *reportSize = sizeof(SGX_Report);
            OE_THROW(OE_BUFFER_TOO_SMALL);
        }
    }

    /* Check other parameters */
    if (!reportData || !report)
        OE_THROW(OE_INVALID_PARAMETER);

    /* Have host initialize the quote (SGX_InitQuote) */
    {
        if (!(args = (OE_InitQuoteArgs*)calloc_u(1,sizeof(OE_InitQuoteArgs))))
        {
            OE_THROW(OE_OUT_OF_MEMORY);
        }

        OE_TRY(__OE_OCall(OE_FUNC_INIT_QUOTE, (uint64_t)args, NULL));
        memcpy(&targetInfo, &args->targetInfo, sizeof(SGX_TargetInfo));
    }

    /* Create the report */
    OE_TRY((SGX_CreateReport(
        &targetInfo,
        (SGX_ReportData*)reportData,
        (SGX_Report*)report)));

    result = OE_OK;

catch:

#if 0
    if (args)
        free_u(args);
#endif

    return result;
}