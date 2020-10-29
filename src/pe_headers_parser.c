#include "struct.h"

#include <xwinbin/types.h>
#include <xwinbin/err.h>
#include <xwinbin/pe_enum.h>
#include <xwinbin/peinfo.h>
#include <stdint.h>
#include <stddef.h>


/* Location in file where a 4-byte file offset to the PE signature is found */
#define PE_OFF_LOC 0x3c


#define COFF_FILE_HEADER_SIZE 20
#define PE_DATADIR_ENTRY_SIZE 8
#define PE_DATADIR_ENTRY_SIZE 8
#define PE_SECTION_HEADER_SIZE 40
#define PE_OPT_HEADER_MIN_SIZE 96


typedef uint32_t pe_sig_t;


/* PE signature, represented in host endianness.
 * Safe to compare with value read from memory using struct_read_u16_le().
 */
static const pe_sig_t PE_SIGNATURE = ((pe_sig_t)(((pe_sig_t)(uint8_t)'P') | ((pe_sig_t)(uint8_t)'E' << 8)));


static int
pe_file_buf_probe(
    size_t off,
    size_t probe_size,
    size_t file_buf_size,
    uint64_t file_total_size,
    xwb_err_t *err,
    size_t *num_bytes_needed
)
{
    if (struct_probe(off, probe_size, file_buf_size))
    {
        return 1;
    }

    if (off + probe_size <= file_total_size)
    {
        *num_bytes_needed = off + probe_size;
        *err = XWB_E_NEED_MORE_BYTES;
    }
    else
    {
        /* If error is already set, use that */
        if (*err == XWB_E_SUCCESS)
        {
            *err = XWB_E_INVALID_PE_FILE;
        }
    }

    return 0;
}


static int
try_get_and_probe_pe_signature_offset(
    const uint8_t *headbuf,
    size_t headbuf_len,
    size_t *pe_sig_off_or_bytes_needed
)
{
    size_t off;

    off = PE_OFF_LOC;
    if (!struct_probe(off, sizeof(uint32_t), headbuf_len))
    {
        *pe_sig_off_or_bytes_needed = off + sizeof(uint32_t);
        return 0;
    }

    /* Read offset to PE signature + COFF header */
    off = (size_t)struct_read_u32_le(headbuf, &off);

    if (!struct_probe(off, sizeof(uint32_t), headbuf_len))
    {
        *pe_sig_off_or_bytes_needed = off + sizeof(uint32_t);
        return 0;
    }

    *pe_sig_off_or_bytes_needed = off;
    return 1;
}


static xwb_err_t
read_coff_header(const uint8_t *srcbuf, size_t *off, struct coff_file_header *hdr)
{
    hdr->cfh_machine = struct_read_u16_le(srcbuf, off);
    hdr->cfh_num_sections = struct_read_u16_le(srcbuf, off);
    hdr->cfh_time_date_stamp = struct_read_u32_le(srcbuf, off);
    hdr->cfh_pointer_to_symbol_table = struct_read_u32_le(srcbuf, off);
    hdr->cfh_number_of_symbols = struct_read_u32_le(srcbuf, off);
    hdr->cfh_size_of_optional_header = struct_read_u16_le(srcbuf, off);
    hdr->cfh_characteristics = struct_read_u16_le(srcbuf, off);

    if (hdr->cfh_num_sections > PE_MAX_NUM_SECTIONS)
    {
        return XWB_E_INVALID_HEADERS;
    }

    return XWB_E_SUCCESS;
}


static xwb_err_t
read_pe_opt_header(const uint8_t *srcbuf, size_t off_limit, size_t *off, struct pe_opt_header *hdr)
{
    uint16_t    magic;
    size_t      i;

    if (!struct_probe(*off, sizeof(uint16_t), off_limit))
    {
        return XWB_E_INVALID_HEADERS;
    }

    magic = struct_read_u16_le(srcbuf, off);

    if ((magic != PE_IMAGE_OPT_HDR32_MAGIC) && (magic != PE_IMAGE_OPT_HDR64_MAGIC))
    {
        return XWB_E_INVALID_HEADERS;
    }

    if (!struct_probe(*off, 22, off_limit))
    {
        return XWB_E_INVALID_HEADERS;
    }

    hdr->poh_magic = magic;
    hdr->poh_major_linker_version = struct_read_u8(srcbuf, off);
    hdr->poh_minor_linker_version = struct_read_u8(srcbuf, off);
    hdr->poh_size_of_code = struct_read_u32_le(srcbuf, off);
    hdr->poh_size_of_initialized_data = struct_read_u32_le(srcbuf, off);
    hdr->poh_size_of_uninitialized_data = struct_read_u32_le(srcbuf, off);
    hdr->poh_address_of_entrypoint = struct_read_u32_le(srcbuf, off);
    hdr->poh_base_of_code = struct_read_u32_le(srcbuf, off);

    if (magic == PE_IMAGE_OPT_HDR32_MAGIC)
    {
        if (!struct_probe(*off, sizeof(uint32_t), off_limit))
        {
            return XWB_E_INVALID_HEADERS;
        }

        hdr->poh_base_of_data = struct_read_u32_le(srcbuf, off);
    }
    else
    {
        hdr->poh_base_of_data = 0;
    }

    /* At this point, PE32 has consumed 28 bytes, and PE32+ has consumed 24 bytes (per spec). */

    if (magic == PE_IMAGE_OPT_HDR32_MAGIC)
    {
        if (!struct_probe(*off, 68, off_limit))
        {
            return XWB_E_INVALID_HEADERS;
        }

        /* 2.4.2 Windows-Specific Fields */
        hdr->poh_image_base = (uint64_t)struct_read_u32_le(srcbuf, off);
        hdr->poh_section_alignment = struct_read_u32_le(srcbuf, off);
        hdr->poh_file_alignment = struct_read_u32_le(srcbuf, off);
        hdr->poh_os_version_major = struct_read_u16_le(srcbuf, off);
        hdr->poh_os_version_minor = struct_read_u16_le(srcbuf, off);
        hdr->poh_image_version_major = struct_read_u16_le(srcbuf, off);
        hdr->poh_image_version_minor = struct_read_u16_le(srcbuf, off);
        hdr->poh_subsystem_version_major = struct_read_u16_le(srcbuf, off);
        hdr->poh_subsystem_version_minor = struct_read_u16_le(srcbuf, off);
        hdr->poh_win32_version_value = struct_read_u32_le(srcbuf, off);
        hdr->poh_size_of_image = struct_read_u32_le(srcbuf, off);
        hdr->poh_size_of_headers = struct_read_u32_le(srcbuf, off);
        hdr->poh_checksum = struct_read_u32_le(srcbuf, off);
        hdr->poh_subsystem = struct_read_u16_le(srcbuf, off);
        hdr->poh_dll_characteristics = struct_read_u16_le(srcbuf, off);
        hdr->poh_size_of_stack_reserve = (uint64_t)struct_read_u32_le(srcbuf, off);
        hdr->poh_size_of_stack_commit = (uint64_t)struct_read_u32_le(srcbuf, off);
        hdr->poh_size_of_heap_reserve = (uint64_t)struct_read_u32_le(srcbuf, off);
        hdr->poh_size_of_heap_commit = (uint64_t)struct_read_u32_le(srcbuf, off);
        hdr->poh_loaderflags = struct_read_u32_le(srcbuf, off);
        hdr->poh_num_datadir_entries = struct_read_u32_le(srcbuf, off);
    }
    else
    {
        if (!struct_probe(*off, 88, off_limit))
        {
            return XWB_E_INVALID_HEADERS;
        }

        /* 2.4.2 Windows-Specific Fields */
        hdr->poh_image_base = struct_read_u64_le(srcbuf, off);
        hdr->poh_section_alignment = struct_read_u32_le(srcbuf, off);
        hdr->poh_file_alignment = struct_read_u32_le(srcbuf, off);
        hdr->poh_os_version_major = struct_read_u16_le(srcbuf, off);
        hdr->poh_os_version_minor = struct_read_u16_le(srcbuf, off);
        hdr->poh_image_version_major = struct_read_u16_le(srcbuf, off);
        hdr->poh_image_version_minor = struct_read_u16_le(srcbuf, off);
        hdr->poh_subsystem_version_major = struct_read_u16_le(srcbuf, off);
        hdr->poh_subsystem_version_minor = struct_read_u16_le(srcbuf, off);
        hdr->poh_win32_version_value = struct_read_u32_le(srcbuf, off);
        hdr->poh_size_of_image = struct_read_u32_le(srcbuf, off);
        hdr->poh_size_of_headers = struct_read_u32_le(srcbuf, off);
        hdr->poh_checksum = struct_read_u32_le(srcbuf, off);
        hdr->poh_subsystem = struct_read_u16_le(srcbuf, off);
        hdr->poh_dll_characteristics = struct_read_u16_le(srcbuf, off);
        hdr->poh_size_of_stack_reserve = struct_read_u64_le(srcbuf, off);
        hdr->poh_size_of_stack_commit = struct_read_u64_le(srcbuf, off);
        hdr->poh_size_of_heap_reserve = struct_read_u64_le(srcbuf, off);
        hdr->poh_size_of_heap_commit = struct_read_u64_le(srcbuf, off);
        hdr->poh_loaderflags = struct_read_u32_le(srcbuf, off);
        hdr->poh_num_datadir_entries = struct_read_u32_le(srcbuf, off);
    }

    /* At this point, PE32 has consumed 96 bytes, and PE32+ has consumed 112 bytes (per spec). */

    if (hdr->poh_num_datadir_entries > PE_IMAGE_OPT_DD_MAXNUM)
    {
        return XWB_E_INVALID_HEADERS;
    }

    if (!struct_probe(*off, hdr->poh_num_datadir_entries * PE_DATADIR_ENTRY_SIZE, off_limit))
    {
        return XWB_E_INVALID_HEADERS;
    }

    for (i = 0; i < hdr->poh_num_datadir_entries; i++)
    {
        hdr->poh_datadir_entries[i].pde_virtual_address = struct_read_u32_le(srcbuf, off);
        hdr->poh_datadir_entries[i].pde_size = struct_read_u32_le(srcbuf, off);
    }

    for (; i < PE_IMAGE_OPT_DD_MAXNUM; i++)
    {
        hdr->poh_datadir_entries[i].pde_virtual_address = 0;
        hdr->poh_datadir_entries[i].pde_size = 0;
    }

    return XWB_E_SUCCESS;
}


static xwb_err_t
read_section_header(const uint8_t *srcbuf, size_t off_limit, size_t *off, struct pe_section_header *hdr)
{
    size_t i;

    if (!struct_probe(*off, PE_SECTION_HEADER_SIZE, off_limit))
    {
        return XWB_E_INVALID_SECTION_TABLE;
    }

    for (i = 0; i < 8; i++)
    {
        hdr->psh_name[i] = struct_read_char(srcbuf, off);
    }
    hdr->psh_name[8] = 0;

    hdr->psh_virtual_size = struct_read_u32_le(srcbuf, off);
    hdr->psh_virtual_address = struct_read_u32_le(srcbuf, off);
    hdr->psh_size_of_raw_data = struct_read_u32_le(srcbuf, off);
    hdr->psh_pointer_to_raw_data = struct_read_u32_le(srcbuf, off);
    hdr->psh_pointer_to_relocations = struct_read_u32_le(srcbuf, off);
    hdr->psh_pointer_to_linenumbers = struct_read_u32_le(srcbuf, off);
    hdr->psh_number_of_relocations = struct_read_u16_le(srcbuf, off);
    hdr->psh_number_of_linenumbers = struct_read_u16_le(srcbuf, off);
    hdr->psh_characteristics = struct_read_u32_le(srcbuf, off);

    return XWB_E_SUCCESS;
}


static void
zero_out_section_header(struct pe_section_header *hdr)
{
    struct pe_section_header zero_hdr = { { 0 }, };
    *hdr = zero_hdr;
}


xwb_err_t
xwb_parse_pe_headers(
    const uint8_t *headbuf,
    size_t *_headbuf_len,
    uint64_t pe_file_total_len,
    struct pe_header_info *hinfo
)
{
    struct coff_file_header coff_hdr;
    struct pe_opt_header    pe_opt_hdr;
    xwb_err_t               err;
    pe_sig_t                pe_sig;
    size_t                  section_table_off;
    size_t                  headbuf_len;
    size_t                  off;
    size_t                  i;
    int                     is_not_image;

    headbuf_len = *_headbuf_len;

    err = XWB_E_INVALID_PE_FILE;
    if (!pe_file_buf_probe(0, COFF_FILE_HEADER_SIZE, headbuf_len, pe_file_total_len, &err, _headbuf_len))
    {
        return err;
    }

    is_not_image = 0;

    if (try_get_and_probe_pe_signature_offset(headbuf, headbuf_len, &off))
    {
        pe_sig = (pe_sig_t)struct_read_u32_le(headbuf, &off);
        if (pe_sig != PE_SIGNATURE)
        {
            is_not_image = 1;
            off = 0;
        }
    }
    else
    {
        if (off <= pe_file_total_len)
        {
            *_headbuf_len = off;
            return XWB_E_NEED_MORE_BYTES;
        }
        else
        {
            is_not_image = 1;
            off = 0;
        }
    }

    err = XWB_E_INVALID_HEADERS;
    if (!pe_file_buf_probe(off, COFF_FILE_HEADER_SIZE, headbuf_len, pe_file_total_len, &err, _headbuf_len))
    {
        return err;
    }

    hinfo->pmi_coff_file_header_off = off;

    err = read_coff_header(headbuf, &off, &coff_hdr);
    if (err != XWB_E_SUCCESS)
    {
        return err;
    }

    hinfo->pmi_coff_file_header = coff_hdr;

    if (coff_hdr.cfh_size_of_optional_header == 0)
    {
        is_not_image = 1;
    }

    if (coff_hdr.cfh_characteristics & PE_IMAGE_FILE_EXECUTABLE_IMAGE)
    {
        if (is_not_image)
        {
            return XWB_E_INVALID_PE_FILE;
        }
    }
    else
    {
        is_not_image = 1;
    }

    if (is_not_image)
    {
        hinfo->pmi_has_optional_header = 0;
        hinfo->pmi_optional_header_off = XWB_OFF_NOFF;
        section_table_off = off;
    }
    else
    {
        if (coff_hdr.cfh_size_of_optional_header < PE_OPT_HEADER_MIN_SIZE)
        {
            return XWB_E_INVALID_HEADERS;
        }

        err = XWB_E_INVALID_HEADERS;
        if (!pe_file_buf_probe(
            off,
            coff_hdr.cfh_size_of_optional_header,
            headbuf_len,
            pe_file_total_len,
            &err,
            _headbuf_len
        ))
        {
            return err;
        }

        hinfo->pmi_optional_header_off = (xwb_off_t)off;
        section_table_off = off + coff_hdr.cfh_size_of_optional_header;

        err = read_pe_opt_header(headbuf, off + coff_hdr.cfh_size_of_optional_header, &off, &pe_opt_hdr);
        if (err != XWB_E_SUCCESS)
        {
            return err;
        }

        hinfo->pmi_has_optional_header = 1;
        hinfo->pmi_optional_header = pe_opt_hdr;
    }

    off = section_table_off;
    hinfo->pmi_section_table_off = section_table_off;

    err = XWB_E_INVALID_SECTION_TABLE;
    if (!pe_file_buf_probe(
        off,
        coff_hdr.cfh_num_sections * PE_SECTION_HEADER_SIZE,
        headbuf_len,
        pe_file_total_len,
        &err,
        _headbuf_len
    ))
    {
        return err;
    }

    for (i = 0; i < coff_hdr.cfh_num_sections; i++)
    {
        err = read_section_header(
            headbuf,
            section_table_off + coff_hdr.cfh_num_sections * PE_SECTION_HEADER_SIZE,
            &off,
            &hinfo->pmi_section_table[i]
        );
        if (err != XWB_E_SUCCESS)
        {
            return err;
        }
    }

    for (; i < PE_MAX_NUM_SECTIONS; i++)
    {
        zero_out_section_header(&hinfo->pmi_section_table[i]);
    }

    return XWB_E_SUCCESS;
}
