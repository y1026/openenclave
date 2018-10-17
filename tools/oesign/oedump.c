// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT License.

#include <openenclave/bits/defs.h>
#include <openenclave/internal/elf.h>
#include <openenclave/internal/hexdump.h>
#include <openenclave/internal/sgxcreate.h>
#include <openenclave/internal/sgxtypes.h>
#include <openenclave/internal/utils.h>
#include <stdarg.h>
#include <string.h>

size_t errors = 0;

static bool verbose_opt = false;

OE_PRINTF_FORMAT(1, 2)
void err(const char* fmt, ...)
{
    va_list ap;
    va_start(ap, fmt);
    fprintf(stderr, "*** Error: ");
    vfprintf(stderr, fmt, ap);
    fprintf(stderr, "\n");
    va_end(ap);
    errors++;
}

void dump_entry_point(elf64_t* elf)
{
    elf64_sym_t sym;
    const char* name;

    if (elf64_find_dynamic_symbol_by_address(
            elf, elf64_get_header(elf)->e_entry, STT_FUNC, &sym) != 0)
    {
        err("cannot find entry point symbol");
        return;
    }

    if (!(name = elf64_get_string_from_dynstr(elf, sym.st_name)))
    {
        err("cannot resolve entry point name");
        return;
    }

    if (strcmp(name, "_start") != 0)
    {
        err("invalid entry point name: %s", name);
        return;
    }

    printf("=== Entry point: \n");
    printf("name=%s\n", name);
    printf("address=%016llx\n", OE_LLX(sym.st_value));
    printf("\n");
}

void dump_enclave_properties(const oe_sgx_enclave_properties_t* props)
{
    const sgx_sigstruct_t* sigstruct;

    printf("=== SGX Enclave Properties:\n");

    printf("product_id=%u\n", props->config.product_id);

    printf("security_version=%u\n", props->config.security_version);

    bool debug = props->config.attributes & OE_SGX_FLAGS_DEBUG;
    printf("debug=%u\n", debug);

    printf(
        "num_heap_pages=%llu\n",
        OE_LLU(props->header.size_settings.num_heap_pages));

    printf(
        "num_stack_pages=%llu\n",
        OE_LLU(props->header.size_settings.num_stack_pages));

    printf("num_tcs=%llu\n", OE_LLU(props->header.size_settings.num_tcs));

    sigstruct = (const sgx_sigstruct_t*)props->sigstruct;

    printf("mrenclave=");
    oe_hex_dump(sigstruct->enclavehash, sizeof(sigstruct->enclavehash));

    printf("signature=");
    oe_hex_dump(sigstruct->signature, sizeof(sigstruct->signature));

    printf("\n");

    if (verbose_opt)
        __sgx_dump_sigstruct(sigstruct);
}

typedef struct _visit_sym_data
{
    const elf64_t* elf;
    const elf64_shdr_t* shdr;
    oe_result_t result;
} visit_sym_data_t;

static int _visit_sym(const elf64_sym_t* sym, void* data_)
{
    int rc = -1;
    visit_sym_data_t* data = (visit_sym_data_t*)data_;
    const elf64_shdr_t* shdr = data->shdr;
    const char* name;

    data->result = OE_UNEXPECTED;

    /* Skip symbol if not a function */
    if ((sym->st_info & 0x0F) != STT_FUNC)
    {
        rc = 0;
        goto done;
    }

    /* Skip symbol if not in the ".ecall" section */
    if (sym->st_value < shdr->sh_addr ||
        sym->st_value + sym->st_size > shdr->sh_addr + shdr->sh_size)
    {
        rc = 0;
        goto done;
    }

    /* Skip null names */
    if (!(name = elf64_get_string_from_dynstr(data->elf, sym->st_name)))
    {
        rc = 0;
        goto done;
    }

    /* Dump the ECALL name */
    printf("%s (%016llx)\n", name, OE_LLX(sym->st_value));

    rc = 0;

done:
    return rc;
}

void dump_ecall_section(elf64_t* elf)
{
    elf64_shdr_t shdr;

    printf("=== ECALLs:\n");

    /* Find the .ecall section */
    if (elf64_find_section_header(elf, ".ecall", &shdr) != 0)
    {
        err("missing .ecall section");
        return;
    }

    /* Dump all the ECALLs */
    {
        visit_sym_data_t data;
        data.elf = elf;
        data.shdr = &shdr;

        if (elf64_visit_symbols(elf, _visit_sym, &data) != 0)
        {
            err("failed to find ECALLs in .ecall section");
            return;
        }
    }

    printf("\n");
}

void check_global(elf64_t* elf, const char* name)
{
    elf64_sym_t sym;

    if (elf64_find_dynamic_symbol_by_name(elf, name, &sym) != 0)
    {
        err("failed to find required symbol: %s\n", name);
        return;
    }

    printf("%s (%016llx)\n", name, OE_LLX(sym.st_value));
}

void check_globals(elf64_t* elf)
{
    printf("=== Globals:\n");

    check_global(elf, "oe_num_pages");
    check_global(elf, "oe_virtual_base_addr");
    check_global(elf, "oe_base_reloc_page");
    check_global(elf, "oe_num_reloc_pages");
    check_global(elf, "oe_base_ecall_page");
    check_global(elf, "oe_num_ecall_pages");
    check_global(elf, "oe_base_heap_page");
    check_global(elf, "oe_num_heap_pages");

    printf("\n");
}

void oedump(const char* arg0, const char* enc_bin, const char* option)
{
    elf64_t elf;
    oe_sgx_enclave_properties_t props;

    if ((strcmp(option, "--oedump") != 0))
    {
        fprintf(stderr, "Usage: %s EnclaveImage --oedump\n", arg0);
        return;
    }

    /* Load the ELF-64 object */
    if (elf64_load(enc_bin, &elf) != 0)
    {
        fprintf(stderr, "failed to load %s\n", enc_bin);
        goto done;
    }

    /* Load the SGX enclave properties */
    if (oe_sgx_load_properties(&elf, OE_INFO_SECTION_NAME, &props) != OE_OK)
    {
        err("failed to load SGX enclave properties from %s section",
            OE_INFO_SECTION_NAME);
    }

    printf("\n");

    /* Dump the entry point */
    dump_entry_point(&elf);

    /* Dump the signature section */
    dump_enclave_properties(&props);

    /* Dump the ECALL section */
    dump_ecall_section(&elf);

    /* Check globals */
    check_globals(&elf);

    if (errors)
    {
        fprintf(stderr, "*** Found %zu errors\n", errors);
        goto done;
    }

done:
    elf64_unload(&elf);
    return;
}
