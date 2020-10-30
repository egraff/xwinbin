#include <xwinbin/peinfo.h>

#include <assert.h>
#include <string.h>
#include <stdio.h>
#include <stdint.h>


extern
xwb_err_t
xwb_parse_pe_headers(
    const uint8_t *headbuf,
    size_t *_headbuf_len,
    uint64_t pe_file_total_len,
    struct pe_header_info *hinfo
);


static void
test_parser_needs_at_least_twenty_bytes(void)
{
    struct pe_header_info   hinfo;
    const uint8_t           bytes = 0;
    xwb_err_t               err;
    size_t                  len;
    size_t                  i;

    for (i = 0; i < 20; i++)
    {
        len = i;
        err = xwb_parse_pe_headers(&bytes, &len, 20, &hinfo);
        assert(err == XWB_E_NEED_MORE_BYTES);
        assert(len == 20);
    }

    for (i = 0; i < 20; i++)
    {
        len = i;
        err = xwb_parse_pe_headers(&bytes, &len, 19, &hinfo);
        assert(err == XWB_E_INVALID_PE_FILE);
    }
}


static void
test_invalid_object_file__missing_section_headers(void)
{
    const uint8_t nsec = 16;

    /* Object file COFF header, no opt header, indicates section header with 16 sections */
    const uint8_t bytes[] =
    {
        0x64, 0x86, nsec, 0x00, 0x00, 0x00, 0x00, 0x00,
        0xb8, 0xdc, 0x00, 0x00, 0x3c, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x04, 0x00,
    };

    struct pe_header_info   hinfo;
    xwb_err_t               err;
    size_t                  len;

    len = sizeof(bytes);
    err = xwb_parse_pe_headers(bytes, &len, len, &hinfo);
    assert(err == XWB_E_INVALID_SECTION_TABLE);
}


static void
test_valid_object_file__no_section_headers(void)
{
    /* Object file COFF header, no opt header, no section headers */
    const uint8_t bytes[] =
    {
        0x64, 0x86, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0xb8, 0xdc, 0x00, 0x00, 0x3c, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x04, 0x00,
    };

    struct pe_header_info   hinfo;
    xwb_err_t               err;
    size_t                  len;

    len = sizeof(bytes);
    err = xwb_parse_pe_headers(bytes, &len, len, &hinfo);
    assert(err == XWB_E_SUCCESS);

    assert(hinfo.pmi_coff_file_header_off == 0);
    assert(hinfo.pmi_coff_file_header.cfh_num_sections == 0);
    assert(hinfo.pmi_coff_file_header.cfh_size_of_optional_header == 0);
    assert(hinfo.pmi_has_optional_header == 0);
    assert(hinfo.pmi_optional_header_off == XWB_OFF_NOFF);
    assert(hinfo.pmi_section_table_off == 20);
}


static void
test_valid_object_file__no_section_headers_and_file_size_less_than_sixtyfour_bytes(void)
{
    /* Object file COFF header, no opt header, no section headers */
    const uint8_t bytes[] =
    {
        0x64, 0x86, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0xb8, 0xdc, 0x00, 0x00, 0x3c, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x04, 0x00,
    };

    struct pe_header_info   hinfo;
    xwb_err_t               err;
    size_t                  file_size;
    size_t                  len;

    for (file_size = sizeof(bytes); file_size < 64; file_size++)
    {
        len = sizeof(bytes);
        err = xwb_parse_pe_headers(bytes, &len, file_size, &hinfo);
        assert(err == XWB_E_SUCCESS);
    }
}


static void
test_valid_object_file__one_section_header_and_file_size_less_than_sixtyfour_bytes(void)
{
    /* Object file COFF header, no opt header, one section header */
    const uint8_t bytes[] =
    {
        0x64, 0x86, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00,
        0xb8, 0xdc, 0x00, 0x00, 0x3c, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x04, 0x00,
    };

    struct pe_header_info   hinfo;
    xwb_err_t               err;
    size_t                  len;
    size_t                  file_size;

    for (file_size = sizeof(bytes) + 40; file_size < 64; file_size++)
    {
        len = sizeof(bytes);
        err = xwb_parse_pe_headers(bytes, &len, file_size, &hinfo);
        assert(err == XWB_E_NEED_MORE_BYTES);
        assert(len == sizeof(bytes) + 40);
    }
}


static void
test_valid_object_file__one_section_header_and_file_size_equal_to_sixtyfour_bytes(void)
{
    /* Object file COFF header, no opt header, one section header */
    const uint8_t bytes[] =
    {
        0x64, 0x86, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00,
        0xb8, 0xdc, 0x00, 0x00, 0x3c, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x04, 0x00,
    };

    struct pe_header_info   hinfo;
    xwb_err_t               err;
    size_t                  len;

    len = sizeof(bytes);
    err = xwb_parse_pe_headers(bytes, &len, 64, &hinfo);
    assert(err == XWB_E_NEED_MORE_BYTES);
    assert(len == 64);
}


static void
test_invalid_object_file__more_than_one_section_header_and_file_size_equal_to_sixtyfour_bytes__missing_section_headers(void)
{
    /* Object file COFF header, no opt header, one section header */
    const uint8_t bytes[] =
    {
        0x64, 0x86, 0x10, 0x00, 0x00, 0x00, 0x00, 0x00,
        0xb8, 0xdc, 0x00, 0x00, 0x3c, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x04, 0x00,
    };

    struct pe_header_info   hinfo;
    xwb_err_t               err;
    size_t                  len;

    len = sizeof(bytes);
    err = xwb_parse_pe_headers(bytes, &len, 64, &hinfo);

    /* NOTE: this is actually an invalid object file, because file size is smaller than the number of bytes required
     * to read all section headers, but parser can't know that in this state, because it might be an image file and
     * not an object file, so more memory is required to determine the outcome.
     */
    assert(err == XWB_E_NEED_MORE_BYTES);
    assert(len == 64);
}


static void
test_invalid_object_file__more_than_one_section_header_and_file_size_equal_to_sixtyfour_bytes(void)
{
    /* Object file COFF header, no opt header, indicates section header with 16 sections */
    const uint8_t bytes[64] =
    {
        0x64, 0x86, 0x10, 0x00, 0x00, 0x00, 0x00, 0x00,
        0xb8, 0xdc, 0x00, 0x00, 0x3c, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x04, 0x00,

        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00,
    };

    struct pe_header_info   hinfo;
    xwb_err_t               err;
    size_t                  len;

    len = sizeof(bytes);
    err = xwb_parse_pe_headers(bytes, &len, sizeof(bytes), &hinfo);
    assert(err == XWB_E_INVALID_SECTION_TABLE);
}


static void
test_valid_object_file__file_size_equal_to_sixtyfour_bytes_and_possible_pe_signature_offset(void)
{
    const uint8_t bytes[64] =
    {
        0x64, 0x86, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0xb8, 0xdc, 0x00, 0x00, 0x3c, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x04, 0x00,

        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x40, 0x00, 0x00, 0x00,
    };

    struct pe_header_info   hinfo;
    xwb_err_t               err;
    size_t                  len;

    len = sizeof(bytes);
    err = xwb_parse_pe_headers(bytes, &len, len, &hinfo);
    assert(err == XWB_E_SUCCESS);
}


static void
test_valid_object_file__buffer_without_all_section_headers(void)
{
    const uint8_t nsec = 16;

    /* Object file COFF header, no opt header, indicates section header with 16 sections */
    const uint8_t bytes[] =
    {
        0x64, 0x86, nsec, 0x00, 0x00, 0x00, 0x00, 0x00,
        0xb8, 0xdc, 0x00, 0x00, 0x3c, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x04, 0x00,

        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00,
    };

    struct pe_header_info   hinfo;
    xwb_err_t               err;
    size_t                  len;

    len = sizeof(bytes);
    err = xwb_parse_pe_headers(bytes, &len, 20 + (nsec * 40), &hinfo);
    assert(err == XWB_E_NEED_MORE_BYTES);
    assert(len == 20 + ((size_t)nsec * 40));
}


static void
test_invalid_object_file__too_many_sections(void)
{
    const uint8_t nsec = 97;

    const uint8_t bytes[64] =
    {
        0x64, 0x86, nsec, 0x00, 0x00, 0x00, 0x00, 0x00,
        0xb8, 0xdc, 0x00, 0x00, 0x3c, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x04, 0x00,

        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00,
    };

    struct pe_header_info   hinfo;
    xwb_err_t               err;
    size_t                  len;

    len = sizeof(bytes);
    err = xwb_parse_pe_headers(bytes, &len, sizeof(bytes) + (nsec * 40), &hinfo);
    assert(err == XWB_E_INVALID_HEADERS);
}


static void
test_valid_pe64_image__no_pe_signature(void)
{
    const uint8_t bytes[64] =
    {
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x40, 0x00, 0x00, 0x00,
    };

    struct pe_header_info   hinfo;
    xwb_err_t               err;
    size_t                  len;

    len = sizeof(bytes);
    err = xwb_parse_pe_headers(bytes, &len, 88 + 240, &hinfo);
    assert(err == XWB_E_NEED_MORE_BYTES);
    assert(len == 68);
}


static void
test_valid_pe64_image__no_coff_header(void)
{
    const uint8_t bytes[68] =
    {
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x40, 0x00, 0x00, 0x00,
        0x50, 0x45, 0x00, 0x00,
    };

    struct pe_header_info   hinfo;
    xwb_err_t               err;
    size_t                  len;

    len = sizeof(bytes);
    err = xwb_parse_pe_headers(bytes, &len, 88 + 240, &hinfo);
    assert(err == XWB_E_NEED_MORE_BYTES);
    assert(len == 88);
}


static void
test_invalid_pe64_image__no_coff_header(void)
{
    const uint8_t bytes[68] =
    {
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x40, 0x00, 0x00, 0x00,
        0x50, 0x45, 0x00, 0x00,
    };

    struct pe_header_info   hinfo;
    xwb_err_t               err;
    size_t                  len;

    len = sizeof(bytes);
    err = xwb_parse_pe_headers(bytes, &len, len, &hinfo);
    assert(err == XWB_E_INVALID_HEADERS);
}


static void
test_valid_pe64_image__no_section_headers(void)
{
    const uint8_t bytes[88] =
    {
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x40, 0x00, 0x00, 0x00,
        0x50, 0x45, 0x00, 0x00,

        0x64, 0x86, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0xb8, 0xdc, 0x00, 0x00, 0x3c, 0x00, 0x00, 0x00,
        0xf0, 0x00, 0x22, 0x00,
    };

    struct pe_header_info   hinfo;
    xwb_err_t               err;
    size_t                  len;

    len = sizeof(bytes);
    err = xwb_parse_pe_headers(bytes, &len, 88 + 240, &hinfo);
    assert(err == XWB_E_NEED_MORE_BYTES);
}


static void
test_invalid_pe64_image__optional_header_size_is_zero(void)
{
    const uint8_t bytes[88] =
    {
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x40, 0x00, 0x00, 0x00,
        0x50, 0x45, 0x00, 0x00,

        0x64, 0x86, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0xb8, 0xdc, 0x00, 0x00, 0x3c, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x22, 0x00,
    };

    struct pe_header_info   hinfo;
    xwb_err_t               err;
    size_t                  len;

    len = sizeof(bytes);
    err = xwb_parse_pe_headers(bytes, &len, 88 + 240, &hinfo);
    assert(err == XWB_E_INVALID_PE_FILE);
}


static void
test_invalid_pe64_image__optional_header_size_is_smaller_than_minimum_size(void)
{
    const uint8_t bytes[88] =
    {
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x40, 0x00, 0x00, 0x00,
        0x50, 0x45, 0x00, 0x00,

        0x64, 0x86, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0xb8, 0xdc, 0x00, 0x00, 0x3c, 0x00, 0x00, 0x00,
        0x5f, 0x00, 0x22, 0x00,
    };

    struct pe_header_info   hinfo;
    xwb_err_t               err;
    size_t                  len;

    len = sizeof(bytes);
    err = xwb_parse_pe_headers(bytes, &len, 88 + 240, &hinfo);
    assert(err == XWB_E_INVALID_HEADERS);
}


static void
test_valid_pe64_image__not_enough_optional_header_bytes(void)
{
    const uint8_t bytes[88] =
    {
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x40, 0x00, 0x00, 0x00,
        0x50, 0x45, 0x00, 0x00,

        0x64, 0x86, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0xb8, 0xdc, 0x00, 0x00, 0x3c, 0x00, 0x00, 0x00,
        0x60, 0x00, 0x22, 0x00,
    };

    struct pe_header_info   hinfo;
    xwb_err_t               err;
    size_t                  len;

    len = sizeof(bytes);
    err = xwb_parse_pe_headers(bytes, &len, 88 + 240, &hinfo);
    assert(err == XWB_E_NEED_MORE_BYTES);
    assert(len == 88 + 96);
}


static void
test_valid_pe64_mingw_exe_image__all_headers(void)
{
    const uint8_t bytes[512 * 3] =
    {
        /*** MZ header - 128 bytes ***/

        0x4d, 0x5a, 0x90, 0x00, 0x03, 0x00, 0x00, 0x00,
        0x04, 0x00, 0x00, 0x00, 0xff, 0xff, 0x00, 0x00,
        0xb8, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x40, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x80, 0x00, 0x00, 0x00,
        0x0e, 0x1f, 0xba, 0x0e, 0x00, 0xb4, 0x09, 0xcd,
        0x21, 0xb8, 0x01, 0x4c, 0xcd, 0x21, 0x54, 0x68,
        0x69, 0x73, 0x20, 0x70, 0x72, 0x6f, 0x67, 0x72,
        0x61, 0x6d, 0x20, 0x63, 0x61, 0x6e, 0x6e, 0x6f,
        0x74, 0x20, 0x62, 0x65, 0x20, 0x72, 0x75, 0x6e,
        0x20, 0x69, 0x6e, 0x20, 0x44, 0x4f, 0x53, 0x20,
        0x6d, 0x6f, 0x64, 0x65, 0x2e, 0x0d, 0x0d, 0x0a,
        0x24, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,

        /*** PE signature + COFF header - 4 + 20 bytes ***/
        0x50, 0x45, 0x00, 0x00, 0x64, 0x86, 0x13, 0x00,
        0x55, 0x90, 0x8e, 0x5f, 0x00, 0xae, 0x0a, 0x00,
        0x5b, 0x0d, 0x00, 0x00, 0xf0, 0x00, 0x26, 0x00,

        /*** Optional header - 240 bytes ***/

        /* Common fields */
        0x0b, 0x02, 0x02, 0x23, 0x00, 0xd6, 0x01, 0x00,
        0x00, 0x4e, 0x02, 0x00, 0x00, 0x2a, 0x00, 0x00,
        0xe0, 0x14, 0x00, 0x00, 0x00, 0x10, 0x00, 0x00,

        /* Windows-specific fields */
        0x00, 0x00, 0x40, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x10, 0x00, 0x00, 0x00, 0x02, 0x00, 0x00,
        0x04, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x05, 0x00, 0x02, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x70, 0x0b, 0x00, 0x00, 0x06, 0x00, 0x00,
        0xb7, 0xa8, 0x0c, 0x00, 0x03, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x20, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x10, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x10, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x10, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x10, 0x00, 0x00, 0x00,

        /* Data directories */
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x90, 0x02, 0x00, 0xec, 0x0b, 0x00, 0x00,
        0x00, 0xc0, 0x02, 0x00, 0xe8, 0x04, 0x00, 0x00,
        0x00, 0x40, 0x02, 0x00, 0x54, 0x0c, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0xd0, 0x02, 0x00, 0x80, 0x02, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0xa0, 0x17, 0x02, 0x00, 0x28, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x14, 0x93, 0x02, 0x00, 0xd8, 0x02, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,

        /*** Section table - 760 bytes ***/

        0x2e, 0x74, 0x65, 0x78, 0x74, 0x00, 0x00, 0x00,
        0x28, 0xd4, 0x01, 0x00, 0x00, 0x10, 0x00, 0x00,
        0x00, 0xd6, 0x01, 0x00, 0x00, 0x06, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x60, 0x00, 0x50, 0x60,

        0x2e, 0x64, 0x61, 0x74, 0x61, 0x00, 0x00, 0x00,
        0x20, 0x18, 0x00, 0x00, 0x00, 0xf0, 0x01, 0x00,
        0x00, 0x1a, 0x00, 0x00, 0x00, 0xdc, 0x01, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x40, 0x00, 0x60, 0xc0,

        0x2e, 0x72, 0x64, 0x61, 0x74, 0x61, 0x00, 0x00,
        0x90, 0x26, 0x00, 0x00, 0x00, 0x10, 0x02, 0x00,
        0x00, 0x28, 0x00, 0x00, 0x00, 0xf6, 0x01, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x40, 0x00, 0x60, 0x40,

        0x2e, 0x70, 0x64, 0x61, 0x74, 0x61, 0x00, 0x00,
        0x54, 0x0c, 0x00, 0x00, 0x00, 0x40, 0x02, 0x00,
        0x00, 0x0e, 0x00, 0x00, 0x00, 0x1e, 0x02, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x40, 0x00, 0x30, 0x40,

        0x2e, 0x78, 0x64, 0x61, 0x74, 0x61, 0x00, 0x00,
        0x70, 0x0c, 0x00, 0x00, 0x00, 0x50, 0x02, 0x00,
        0x00, 0x0e, 0x00, 0x00, 0x00, 0x2c, 0x02, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x40, 0x00, 0x30, 0x40,

        0x2e, 0x62, 0x73, 0x73, 0x00, 0x00, 0x00, 0x00,
        0x60, 0x28, 0x00, 0x00, 0x00, 0x60, 0x02, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x80, 0x00, 0x60, 0xc0,

        0x2e, 0x69, 0x64, 0x61, 0x74, 0x61, 0x00, 0x00,
        0xec, 0x0b, 0x00, 0x00, 0x00, 0x90, 0x02, 0x00,
        0x00, 0x0c, 0x00, 0x00, 0x00, 0x3a, 0x02, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x40, 0x00, 0x30, 0xc0,

        0x2e, 0x43, 0x52, 0x54, 0x00, 0x00, 0x00, 0x00,
        0x68, 0x00, 0x00, 0x00, 0x00, 0xa0, 0x02, 0x00,
        0x00, 0x02, 0x00, 0x00, 0x00, 0x46, 0x02, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x40, 0x00, 0x40, 0xc0,

        0x2e, 0x74, 0x6c, 0x73, 0x00, 0x00, 0x00, 0x00,
        0x10, 0x00, 0x00, 0x00, 0x00, 0xb0, 0x02, 0x00,
        0x00, 0x02, 0x00, 0x00, 0x00, 0x48, 0x02, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x40, 0x00, 0x40, 0xc0,

        0x2e, 0x72, 0x73, 0x72, 0x63, 0x00, 0x00, 0x00,
        0xe8, 0x04, 0x00, 0x00, 0x00, 0xc0, 0x02, 0x00,
        0x00, 0x06, 0x00, 0x00, 0x00, 0x4a, 0x02, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x40, 0x00, 0x30, 0xc0,

        0x2e, 0x72, 0x65, 0x6c, 0x6f, 0x63, 0x00, 0x00,
        0x80, 0x02, 0x00, 0x00, 0x00, 0xd0, 0x02, 0x00,
        0x00, 0x04, 0x00, 0x00, 0x00, 0x50, 0x02, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x40, 0x00, 0x30, 0x42,

        0x2f, 0x34, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x30, 0x0b, 0x00, 0x00, 0x00, 0xe0, 0x02, 0x00,
        0x00, 0x0c, 0x00, 0x00, 0x00, 0x54, 0x02, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x40, 0x00, 0x10, 0x42,

        0x2f, 0x31, 0x39, 0x00, 0x00, 0x00, 0x00, 0x00,
        0xd6, 0x81, 0x02, 0x00, 0x00, 0xf0, 0x02, 0x00,
        0x00, 0x82, 0x02, 0x00, 0x00, 0x60, 0x02, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x40, 0x00, 0x10, 0x42,

        0x2f, 0x33, 0x31, 0x00, 0x00, 0x00, 0x00, 0x00,
        0xd5, 0x5a, 0x00, 0x00, 0x00, 0x80, 0x05, 0x00,
        0x00, 0x5c, 0x00, 0x00, 0x00, 0xe2, 0x04, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x40, 0x00, 0x10, 0x42,

        0x2f, 0x34, 0x35, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x81, 0x62, 0x01, 0x00, 0x00, 0xe0, 0x05, 0x00,
        0x00, 0x64, 0x01, 0x00, 0x00, 0x3e, 0x05, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x40, 0x00, 0x10, 0x42,

        0x2f, 0x35, 0x37, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x38, 0x00, 0x00, 0x00, 0x50, 0x07, 0x00,
        0x00, 0x38, 0x00, 0x00, 0x00, 0xa2, 0x06, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x40, 0x00, 0x40, 0x42,

        0x2f, 0x37, 0x30, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x81, 0x0d, 0x00, 0x00, 0x00, 0x90, 0x07, 0x00,
        0x00, 0x0e, 0x00, 0x00, 0x00, 0xda, 0x06, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x40, 0x00, 0x10, 0x42,

        0x2f, 0x38, 0x31, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x4d, 0x8a, 0x03, 0x00, 0x00, 0xa0, 0x07, 0x00,
        0x00, 0x8c, 0x03, 0x00, 0x00, 0xe8, 0x06, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x40, 0x00, 0x10, 0x42,

        0x2f, 0x39, 0x32, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x80, 0x38, 0x00, 0x00, 0x00, 0x30, 0x0b, 0x00,
        0x00, 0x3a, 0x00, 0x00, 0x00, 0x74, 0x0a, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x40, 0x00, 0x10, 0x42,
    };

    struct pe_header_info   hinfo;
    xwb_err_t               err;
    size_t                  len;

    len = 1152;
    err = xwb_parse_pe_headers(bytes, &len, 512 * 3, &hinfo);
    assert(err == XWB_E_SUCCESS);

    assert(hinfo.pmi_coff_file_header_off == 128 + 4);

    /* COFF file header */
    assert(hinfo.pmi_coff_file_header.cfh_machine == PE_IMAGE_FILE_MACHINE_AMD64);
    assert(hinfo.pmi_coff_file_header.cfh_num_sections == 19);
    assert(hinfo.pmi_coff_file_header.cfh_time_date_stamp == 0x5f8e9055);
    assert(hinfo.pmi_coff_file_header.cfh_pointer_to_symbol_table == 0x0aae00);
    assert(hinfo.pmi_coff_file_header.cfh_number_of_symbols == 3419);
    assert(hinfo.pmi_coff_file_header.cfh_size_of_optional_header == 240);
    assert(hinfo.pmi_coff_file_header.cfh_characteristics == (PE_IMAGE_FILE_EXECUTABLE_IMAGE | PE_IMAGE_FILE_LINE_NUMS_STRIPPED | PE_IMAGE_FILE_LARGE_ADDRESS_AWARE));

    assert(hinfo.pmi_has_optional_header == 1);
    assert(hinfo.pmi_optional_header_off == 128 + 4 + 20);

    /* Optional header - common fields */
    assert(hinfo.pmi_optional_header.poh_magic == PE_IMAGE_OPT_HDR64_MAGIC);
    assert(hinfo.pmi_optional_header.poh_major_linker_version == 2);
    assert(hinfo.pmi_optional_header.poh_minor_linker_version == 35);
    assert(hinfo.pmi_optional_header.poh_size_of_code == 120320);
    assert(hinfo.pmi_optional_header.poh_size_of_initialized_data == 151040);
    assert(hinfo.pmi_optional_header.poh_size_of_uninitialized_data == 10752);
    assert(hinfo.pmi_optional_header.poh_address_of_entrypoint == 0x000014e0);
    assert(hinfo.pmi_optional_header.poh_base_of_code == 0x00001000);
    assert(hinfo.pmi_optional_header.poh_base_of_data == 0);

    /* Optional header - Windows-specific fields */
    assert(hinfo.pmi_optional_header.poh_image_base == 0x0000000000400000ULL);
    assert(hinfo.pmi_optional_header.poh_section_alignment == 4096);
    assert(hinfo.pmi_optional_header.poh_file_alignment == 512);
    assert(hinfo.pmi_optional_header.poh_os_version_major == 4);
    assert(hinfo.pmi_optional_header.poh_os_version_minor == 0);
    assert(hinfo.pmi_optional_header.poh_image_version_major == 0);
    assert(hinfo.pmi_optional_header.poh_image_version_minor == 0);
    assert(hinfo.pmi_optional_header.poh_subsystem_version_major == 5);
    assert(hinfo.pmi_optional_header.poh_subsystem_version_minor == 2);
    assert(hinfo.pmi_optional_header.poh_win32_version_value == 0);
    assert(hinfo.pmi_optional_header.poh_size_of_image == 749568);
    assert(hinfo.pmi_optional_header.poh_size_of_headers == 1536);
    assert(hinfo.pmi_optional_header.poh_checksum == 0x000ca8b7);
    assert(hinfo.pmi_optional_header.poh_subsystem == 3);
    assert(hinfo.pmi_optional_header.poh_dll_characteristics == 0);
    assert(hinfo.pmi_optional_header.poh_size_of_stack_reserve == 2097152);
    assert(hinfo.pmi_optional_header.poh_size_of_stack_commit == 4096);
    assert(hinfo.pmi_optional_header.poh_size_of_heap_reserve == 1048576);
    assert(hinfo.pmi_optional_header.poh_size_of_heap_commit == 4096);
    assert(hinfo.pmi_optional_header.poh_loaderflags == 0);
    assert(hinfo.pmi_optional_header.poh_num_datadir_entries == 16);

    /* Optional header - data directories */
    assert(hinfo.pmi_optional_header.poh_datadir_entries[PE_IMAGE_OPT_DD_OFF_EXPORT].pde_virtual_address == 0);
    assert(hinfo.pmi_optional_header.poh_datadir_entries[PE_IMAGE_OPT_DD_OFF_EXPORT].pde_size == 0);
    assert(hinfo.pmi_optional_header.poh_datadir_entries[PE_IMAGE_OPT_DD_OFF_IMPORT].pde_virtual_address == 0x00029000);
    assert(hinfo.pmi_optional_header.poh_datadir_entries[PE_IMAGE_OPT_DD_OFF_IMPORT].pde_size == 3052);
    assert(hinfo.pmi_optional_header.poh_datadir_entries[PE_IMAGE_OPT_DD_OFF_RESOURCE].pde_virtual_address == 0x0002c000);
    assert(hinfo.pmi_optional_header.poh_datadir_entries[PE_IMAGE_OPT_DD_OFF_RESOURCE].pde_size == 1256);
    assert(hinfo.pmi_optional_header.poh_datadir_entries[PE_IMAGE_OPT_DD_OFF_EXCEPTION].pde_virtual_address == 0x00024000);
    assert(hinfo.pmi_optional_header.poh_datadir_entries[PE_IMAGE_OPT_DD_OFF_EXCEPTION].pde_size == 3156);
    assert(hinfo.pmi_optional_header.poh_datadir_entries[PE_IMAGE_OPT_DD_OFF_CERTIFICATE].pde_virtual_address == 0);
    assert(hinfo.pmi_optional_header.poh_datadir_entries[PE_IMAGE_OPT_DD_OFF_CERTIFICATE].pde_size == 0);
    assert(hinfo.pmi_optional_header.poh_datadir_entries[PE_IMAGE_OPT_DD_OFF_RELOCATION].pde_virtual_address == 0x0002d000);
    assert(hinfo.pmi_optional_header.poh_datadir_entries[PE_IMAGE_OPT_DD_OFF_RELOCATION].pde_size == 640);
    assert(hinfo.pmi_optional_header.poh_datadir_entries[PE_IMAGE_OPT_DD_OFF_DEBUG].pde_virtual_address == 0);
    assert(hinfo.pmi_optional_header.poh_datadir_entries[PE_IMAGE_OPT_DD_OFF_DEBUG].pde_size == 0);
    assert(hinfo.pmi_optional_header.poh_datadir_entries[PE_IMAGE_OPT_DD_OFF_ARCH].pde_virtual_address == 0);
    assert(hinfo.pmi_optional_header.poh_datadir_entries[PE_IMAGE_OPT_DD_OFF_ARCH].pde_size == 0);
    assert(hinfo.pmi_optional_header.poh_datadir_entries[PE_IMAGE_OPT_DD_OFF_GLOBALPTR].pde_virtual_address == 0);
    assert(hinfo.pmi_optional_header.poh_datadir_entries[PE_IMAGE_OPT_DD_OFF_GLOBALPTR].pde_size == 0);
    assert(hinfo.pmi_optional_header.poh_datadir_entries[PE_IMAGE_OPT_DD_OFF_TLS].pde_virtual_address == 0x000217a0);
    assert(hinfo.pmi_optional_header.poh_datadir_entries[PE_IMAGE_OPT_DD_OFF_TLS].pde_size == 40);
    assert(hinfo.pmi_optional_header.poh_datadir_entries[PE_IMAGE_OPT_DD_OFF_LOADCONFIG].pde_virtual_address == 0);
    assert(hinfo.pmi_optional_header.poh_datadir_entries[PE_IMAGE_OPT_DD_OFF_LOADCONFIG].pde_size == 0);
    assert(hinfo.pmi_optional_header.poh_datadir_entries[PE_IMAGE_OPT_DD_OFF_BOUNDIMPORT].pde_virtual_address == 0);
    assert(hinfo.pmi_optional_header.poh_datadir_entries[PE_IMAGE_OPT_DD_OFF_BOUNDIMPORT].pde_size == 0);
    assert(hinfo.pmi_optional_header.poh_datadir_entries[PE_IMAGE_OPT_DD_OFF_IAT].pde_virtual_address == 0x00029314);
    assert(hinfo.pmi_optional_header.poh_datadir_entries[PE_IMAGE_OPT_DD_OFF_IAT].pde_size == 728);
    assert(hinfo.pmi_optional_header.poh_datadir_entries[PE_IMAGE_OPT_DD_OFF_DELAYIMPORT].pde_virtual_address == 0);
    assert(hinfo.pmi_optional_header.poh_datadir_entries[PE_IMAGE_OPT_DD_OFF_DELAYIMPORT].pde_size == 0);
    assert(hinfo.pmi_optional_header.poh_datadir_entries[PE_IMAGE_OPT_DD_OFF_CLRRUNTIME].pde_virtual_address == 0);
    assert(hinfo.pmi_optional_header.poh_datadir_entries[PE_IMAGE_OPT_DD_OFF_CLRRUNTIME].pde_size == 0);
    assert(hinfo.pmi_optional_header.poh_datadir_entries[PE_IMAGE_OPT_DD_OFF_RESERVED].pde_virtual_address == 0);
    assert(hinfo.pmi_optional_header.poh_datadir_entries[PE_IMAGE_OPT_DD_OFF_RESERVED].pde_size == 0);

    assert(hinfo.pmi_section_table_off == 128 + 4 + 20 + 240);

    /* Section table */

    assert(strcmp(hinfo.pmi_section_table[0].psh_name, ".text") == 0);
    assert(hinfo.pmi_section_table[0].psh_virtual_size == 119848);
    assert(hinfo.pmi_section_table[0].psh_virtual_address == 0x00001000);
    assert(hinfo.pmi_section_table[0].psh_size_of_raw_data == 120320);
    assert(hinfo.pmi_section_table[0].psh_pointer_to_raw_data == 0x00000600);
    assert(hinfo.pmi_section_table[0].psh_pointer_to_relocations == 0);
    assert(hinfo.pmi_section_table[0].psh_pointer_to_linenumbers == 0);
    assert(hinfo.pmi_section_table[0].psh_number_of_relocations == 0);
    assert(hinfo.pmi_section_table[0].psh_number_of_linenumbers == 0);
    assert(hinfo.pmi_section_table[0].psh_characteristics == (PE_IMAGE_SCN_MEM_READ | PE_IMAGE_SCN_MEM_EXECUTE | 0x00500000 | PE_IMAGE_SCN_CNT_INITIALIZED_DATA | PE_IMAGE_SCN_CNT_CODE));

    assert(strcmp(hinfo.pmi_section_table[1].psh_name, ".data") == 0);
    assert(hinfo.pmi_section_table[1].psh_virtual_size == 6176);
    assert(hinfo.pmi_section_table[1].psh_virtual_address == 0x0001f000);
    assert(hinfo.pmi_section_table[1].psh_size_of_raw_data == 6656);
    assert(hinfo.pmi_section_table[1].psh_pointer_to_raw_data == 0x0001dc00);
    assert(hinfo.pmi_section_table[1].psh_pointer_to_relocations == 0);
    assert(hinfo.pmi_section_table[1].psh_pointer_to_linenumbers == 0);
    assert(hinfo.pmi_section_table[1].psh_number_of_relocations == 0);
    assert(hinfo.pmi_section_table[1].psh_number_of_linenumbers == 0);
    assert(hinfo.pmi_section_table[1].psh_characteristics == (PE_IMAGE_SCN_MEM_WRITE | PE_IMAGE_SCN_MEM_READ | 0x00600000 | PE_IMAGE_SCN_CNT_INITIALIZED_DATA));

    assert(strcmp(hinfo.pmi_section_table[2].psh_name, ".rdata") == 0);
    assert(hinfo.pmi_section_table[2].psh_virtual_size == 9872);
    assert(hinfo.pmi_section_table[2].psh_virtual_address == 0x00021000);
    assert(hinfo.pmi_section_table[2].psh_size_of_raw_data == 10240);
    assert(hinfo.pmi_section_table[2].psh_pointer_to_raw_data == 0x0001f600);
    assert(hinfo.pmi_section_table[2].psh_pointer_to_relocations == 0);
    assert(hinfo.pmi_section_table[2].psh_pointer_to_linenumbers == 0);
    assert(hinfo.pmi_section_table[2].psh_number_of_relocations == 0);
    assert(hinfo.pmi_section_table[2].psh_number_of_linenumbers == 0);
    assert(hinfo.pmi_section_table[2].psh_characteristics == (PE_IMAGE_SCN_MEM_READ | 0x00600000 | PE_IMAGE_SCN_CNT_INITIALIZED_DATA));

    assert(strcmp(hinfo.pmi_section_table[3].psh_name, ".pdata") == 0);
    assert(hinfo.pmi_section_table[3].psh_virtual_size == 3156);
    assert(hinfo.pmi_section_table[3].psh_virtual_address == 0x00024000);
    assert(hinfo.pmi_section_table[3].psh_size_of_raw_data == 3584);
    assert(hinfo.pmi_section_table[3].psh_pointer_to_raw_data == 0x00021e00);
    assert(hinfo.pmi_section_table[3].psh_pointer_to_relocations == 0);
    assert(hinfo.pmi_section_table[3].psh_pointer_to_linenumbers == 0);
    assert(hinfo.pmi_section_table[3].psh_number_of_relocations == 0);
    assert(hinfo.pmi_section_table[3].psh_number_of_linenumbers == 0);
    assert(hinfo.pmi_section_table[3].psh_characteristics == (PE_IMAGE_SCN_MEM_READ | 0x00300000 | PE_IMAGE_SCN_CNT_INITIALIZED_DATA));

    assert(strcmp(hinfo.pmi_section_table[4].psh_name, ".xdata") == 0);
    assert(hinfo.pmi_section_table[4].psh_virtual_size == 3184);
    assert(hinfo.pmi_section_table[4].psh_virtual_address == 0x00025000);
    assert(hinfo.pmi_section_table[4].psh_size_of_raw_data == 3584);
    assert(hinfo.pmi_section_table[4].psh_pointer_to_raw_data == 0x00022c00);
    assert(hinfo.pmi_section_table[4].psh_pointer_to_relocations == 0);
    assert(hinfo.pmi_section_table[4].psh_pointer_to_linenumbers == 0);
    assert(hinfo.pmi_section_table[4].psh_number_of_relocations == 0);
    assert(hinfo.pmi_section_table[4].psh_number_of_linenumbers == 0);
    assert(hinfo.pmi_section_table[4].psh_characteristics == (PE_IMAGE_SCN_MEM_READ | 0x00300000 | PE_IMAGE_SCN_CNT_INITIALIZED_DATA));

    assert(strcmp(hinfo.pmi_section_table[5].psh_name, ".bss") == 0);
    assert(hinfo.pmi_section_table[5].psh_virtual_size == 10336);
    assert(hinfo.pmi_section_table[5].psh_virtual_address == 0x00026000);
    assert(hinfo.pmi_section_table[5].psh_size_of_raw_data == 0);
    assert(hinfo.pmi_section_table[5].psh_pointer_to_raw_data == 0);
    assert(hinfo.pmi_section_table[5].psh_pointer_to_relocations == 0);
    assert(hinfo.pmi_section_table[5].psh_pointer_to_linenumbers == 0);
    assert(hinfo.pmi_section_table[5].psh_number_of_relocations == 0);
    assert(hinfo.pmi_section_table[5].psh_number_of_linenumbers == 0);
    assert(hinfo.pmi_section_table[5].psh_characteristics == (PE_IMAGE_SCN_MEM_WRITE | PE_IMAGE_SCN_MEM_READ | 0x00600000 | PE_IMAGE_SCN_CNT_UNINITIALIZED_DATA));

    assert(strcmp(hinfo.pmi_section_table[6].psh_name, ".idata") == 0);
    assert(hinfo.pmi_section_table[6].psh_virtual_size == 3052);
    assert(hinfo.pmi_section_table[6].psh_virtual_address == 0x00029000);
    assert(hinfo.pmi_section_table[6].psh_size_of_raw_data == 3072);
    assert(hinfo.pmi_section_table[6].psh_pointer_to_raw_data == 0x00023a00);
    assert(hinfo.pmi_section_table[6].psh_pointer_to_relocations == 0);
    assert(hinfo.pmi_section_table[6].psh_pointer_to_linenumbers == 0);
    assert(hinfo.pmi_section_table[6].psh_number_of_relocations == 0);
    assert(hinfo.pmi_section_table[6].psh_number_of_linenumbers == 0);
    assert(hinfo.pmi_section_table[6].psh_characteristics == (PE_IMAGE_SCN_MEM_WRITE | PE_IMAGE_SCN_MEM_READ | 0x00300000 | PE_IMAGE_SCN_CNT_INITIALIZED_DATA));

    assert(strcmp(hinfo.pmi_section_table[7].psh_name, ".CRT") == 0);
    assert(hinfo.pmi_section_table[7].psh_virtual_size == 104);
    assert(hinfo.pmi_section_table[7].psh_virtual_address == 0x0002a000);
    assert(hinfo.pmi_section_table[7].psh_size_of_raw_data == 512);
    assert(hinfo.pmi_section_table[7].psh_pointer_to_raw_data == 0x00024600);
    assert(hinfo.pmi_section_table[7].psh_pointer_to_relocations == 0);
    assert(hinfo.pmi_section_table[7].psh_pointer_to_linenumbers == 0);
    assert(hinfo.pmi_section_table[7].psh_number_of_relocations == 0);
    assert(hinfo.pmi_section_table[7].psh_number_of_linenumbers == 0);
    assert(hinfo.pmi_section_table[7].psh_characteristics == (PE_IMAGE_SCN_MEM_WRITE | PE_IMAGE_SCN_MEM_READ | 0x00400000 | PE_IMAGE_SCN_CNT_INITIALIZED_DATA));

    assert(strcmp(hinfo.pmi_section_table[8].psh_name, ".tls") == 0);
    assert(hinfo.pmi_section_table[8].psh_virtual_size == 16);
    assert(hinfo.pmi_section_table[8].psh_virtual_address == 0x0002b000);
    assert(hinfo.pmi_section_table[8].psh_size_of_raw_data == 512);
    assert(hinfo.pmi_section_table[8].psh_pointer_to_raw_data == 0x00024800);
    assert(hinfo.pmi_section_table[8].psh_pointer_to_relocations == 0);
    assert(hinfo.pmi_section_table[8].psh_pointer_to_linenumbers == 0);
    assert(hinfo.pmi_section_table[8].psh_number_of_relocations == 0);
    assert(hinfo.pmi_section_table[8].psh_number_of_linenumbers == 0);
    assert(hinfo.pmi_section_table[8].psh_characteristics == (PE_IMAGE_SCN_MEM_WRITE | PE_IMAGE_SCN_MEM_READ | 0x00400000 | PE_IMAGE_SCN_CNT_INITIALIZED_DATA));

    assert(strcmp(hinfo.pmi_section_table[9].psh_name, ".rsrc") == 0);
    assert(hinfo.pmi_section_table[9].psh_virtual_size == 1256);
    assert(hinfo.pmi_section_table[9].psh_virtual_address == 0x0002c000);
    assert(hinfo.pmi_section_table[9].psh_size_of_raw_data == 1536);
    assert(hinfo.pmi_section_table[9].psh_pointer_to_raw_data == 0x00024a00);
    assert(hinfo.pmi_section_table[9].psh_pointer_to_relocations == 0);
    assert(hinfo.pmi_section_table[9].psh_pointer_to_linenumbers == 0);
    assert(hinfo.pmi_section_table[9].psh_number_of_relocations == 0);
    assert(hinfo.pmi_section_table[9].psh_number_of_linenumbers == 0);
    assert(hinfo.pmi_section_table[9].psh_characteristics == (PE_IMAGE_SCN_MEM_WRITE | PE_IMAGE_SCN_MEM_READ | 0x00300000 | PE_IMAGE_SCN_CNT_INITIALIZED_DATA));

    assert(strcmp(hinfo.pmi_section_table[10].psh_name, ".reloc") == 0);
    assert(hinfo.pmi_section_table[10].psh_virtual_size == 640);
    assert(hinfo.pmi_section_table[10].psh_virtual_address == 0x0002d000);
    assert(hinfo.pmi_section_table[10].psh_size_of_raw_data == 1024);
    assert(hinfo.pmi_section_table[10].psh_pointer_to_raw_data == 0x00025000);
    assert(hinfo.pmi_section_table[10].psh_pointer_to_relocations == 0);
    assert(hinfo.pmi_section_table[10].psh_pointer_to_linenumbers == 0);
    assert(hinfo.pmi_section_table[10].psh_number_of_relocations == 0);
    assert(hinfo.pmi_section_table[10].psh_number_of_linenumbers == 0);
    assert(hinfo.pmi_section_table[10].psh_characteristics == (PE_IMAGE_SCN_MEM_READ | PE_IMAGE_SCN_MEM_DISCARDABLE | 0x00300000 | PE_IMAGE_SCN_CNT_INITIALIZED_DATA));

    assert(strcmp(hinfo.pmi_section_table[11].psh_name, "/4") == 0);
    assert(hinfo.pmi_section_table[11].psh_virtual_size == 2864);
    assert(hinfo.pmi_section_table[11].psh_virtual_address == 0x0002e000);
    assert(hinfo.pmi_section_table[11].psh_size_of_raw_data == 3072);
    assert(hinfo.pmi_section_table[11].psh_pointer_to_raw_data == 0x00025400);
    assert(hinfo.pmi_section_table[11].psh_pointer_to_relocations == 0);
    assert(hinfo.pmi_section_table[11].psh_pointer_to_linenumbers == 0);
    assert(hinfo.pmi_section_table[11].psh_number_of_relocations == 0);
    assert(hinfo.pmi_section_table[11].psh_number_of_linenumbers == 0);
    assert(hinfo.pmi_section_table[11].psh_characteristics == (PE_IMAGE_SCN_MEM_READ | PE_IMAGE_SCN_MEM_DISCARDABLE | 0x00100000 | PE_IMAGE_SCN_CNT_INITIALIZED_DATA));

    assert(strcmp(hinfo.pmi_section_table[12].psh_name, "/19") == 0);
    assert(hinfo.pmi_section_table[12].psh_virtual_size == 164310);
    assert(hinfo.pmi_section_table[12].psh_virtual_address == 0x0002f000);
    assert(hinfo.pmi_section_table[12].psh_size_of_raw_data == 164352);
    assert(hinfo.pmi_section_table[12].psh_pointer_to_raw_data == 0x00026000);
    assert(hinfo.pmi_section_table[12].psh_pointer_to_relocations == 0);
    assert(hinfo.pmi_section_table[12].psh_pointer_to_linenumbers == 0);
    assert(hinfo.pmi_section_table[12].psh_number_of_relocations == 0);
    assert(hinfo.pmi_section_table[12].psh_number_of_linenumbers == 0);
    assert(hinfo.pmi_section_table[12].psh_characteristics == (PE_IMAGE_SCN_MEM_READ | PE_IMAGE_SCN_MEM_DISCARDABLE | 0x00100000 | PE_IMAGE_SCN_CNT_INITIALIZED_DATA));

    assert(strcmp(hinfo.pmi_section_table[13].psh_name, "/31") == 0);
    assert(hinfo.pmi_section_table[13].psh_virtual_size == 23253);
    assert(hinfo.pmi_section_table[13].psh_virtual_address == 0x00058000);
    assert(hinfo.pmi_section_table[13].psh_size_of_raw_data == 23552);
    assert(hinfo.pmi_section_table[13].psh_pointer_to_raw_data == 0x0004e200);
    assert(hinfo.pmi_section_table[13].psh_pointer_to_relocations == 0);
    assert(hinfo.pmi_section_table[13].psh_pointer_to_linenumbers == 0);
    assert(hinfo.pmi_section_table[13].psh_number_of_relocations == 0);
    assert(hinfo.pmi_section_table[13].psh_number_of_linenumbers == 0);
    assert(hinfo.pmi_section_table[13].psh_characteristics == (PE_IMAGE_SCN_MEM_READ | PE_IMAGE_SCN_MEM_DISCARDABLE | 0x00100000 | PE_IMAGE_SCN_CNT_INITIALIZED_DATA));

    assert(strcmp(hinfo.pmi_section_table[14].psh_name, "/45") == 0);
    assert(hinfo.pmi_section_table[14].psh_virtual_size == 90753);
    assert(hinfo.pmi_section_table[14].psh_virtual_address == 0x0005e000);
    assert(hinfo.pmi_section_table[14].psh_size_of_raw_data == 91136);
    assert(hinfo.pmi_section_table[14].psh_pointer_to_raw_data == 0x00053e00);
    assert(hinfo.pmi_section_table[14].psh_pointer_to_relocations == 0);
    assert(hinfo.pmi_section_table[14].psh_pointer_to_linenumbers == 0);
    assert(hinfo.pmi_section_table[14].psh_number_of_relocations == 0);
    assert(hinfo.pmi_section_table[14].psh_number_of_linenumbers == 0);
    assert(hinfo.pmi_section_table[14].psh_characteristics == (PE_IMAGE_SCN_MEM_READ | PE_IMAGE_SCN_MEM_DISCARDABLE | 0x00100000 | PE_IMAGE_SCN_CNT_INITIALIZED_DATA));

    assert(strcmp(hinfo.pmi_section_table[15].psh_name, "/57") == 0);
    assert(hinfo.pmi_section_table[15].psh_virtual_size == 14336);
    assert(hinfo.pmi_section_table[15].psh_virtual_address == 0x00075000);
    assert(hinfo.pmi_section_table[15].psh_size_of_raw_data == 14336);
    assert(hinfo.pmi_section_table[15].psh_pointer_to_raw_data == 0x0006a200);
    assert(hinfo.pmi_section_table[15].psh_pointer_to_relocations == 0);
    assert(hinfo.pmi_section_table[15].psh_pointer_to_linenumbers == 0);
    assert(hinfo.pmi_section_table[15].psh_number_of_relocations == 0);
    assert(hinfo.pmi_section_table[15].psh_number_of_linenumbers == 0);
    assert(hinfo.pmi_section_table[15].psh_characteristics == (PE_IMAGE_SCN_MEM_READ | PE_IMAGE_SCN_MEM_DISCARDABLE | 0x00400000 | PE_IMAGE_SCN_CNT_INITIALIZED_DATA));

    assert(strcmp(hinfo.pmi_section_table[16].psh_name, "/70") == 0);
    assert(hinfo.pmi_section_table[16].psh_virtual_size == 3457);
    assert(hinfo.pmi_section_table[16].psh_virtual_address == 0x00079000);
    assert(hinfo.pmi_section_table[16].psh_size_of_raw_data == 3584);
    assert(hinfo.pmi_section_table[16].psh_pointer_to_raw_data == 0x0006da00);
    assert(hinfo.pmi_section_table[16].psh_pointer_to_relocations == 0);
    assert(hinfo.pmi_section_table[16].psh_pointer_to_linenumbers == 0);
    assert(hinfo.pmi_section_table[16].psh_number_of_relocations == 0);
    assert(hinfo.pmi_section_table[16].psh_number_of_linenumbers == 0);
    assert(hinfo.pmi_section_table[16].psh_characteristics == (PE_IMAGE_SCN_MEM_READ | PE_IMAGE_SCN_MEM_DISCARDABLE | 0x00100000 | PE_IMAGE_SCN_CNT_INITIALIZED_DATA));

    assert(strcmp(hinfo.pmi_section_table[17].psh_name, "/81") == 0);
    assert(hinfo.pmi_section_table[17].psh_virtual_size == 232013);
    assert(hinfo.pmi_section_table[17].psh_virtual_address == 0x0007a000);
    assert(hinfo.pmi_section_table[17].psh_size_of_raw_data == 232448);
    assert(hinfo.pmi_section_table[17].psh_pointer_to_raw_data == 0x0006e800);
    assert(hinfo.pmi_section_table[17].psh_pointer_to_relocations == 0);
    assert(hinfo.pmi_section_table[17].psh_pointer_to_linenumbers == 0);
    assert(hinfo.pmi_section_table[17].psh_number_of_relocations == 0);
    assert(hinfo.pmi_section_table[17].psh_number_of_linenumbers == 0);
    assert(hinfo.pmi_section_table[17].psh_characteristics == (PE_IMAGE_SCN_MEM_READ | PE_IMAGE_SCN_MEM_DISCARDABLE | 0x00100000 | PE_IMAGE_SCN_CNT_INITIALIZED_DATA));

    assert(strcmp(hinfo.pmi_section_table[18].psh_name, "/92") == 0);
    assert(hinfo.pmi_section_table[18].psh_virtual_size == 14464);
    assert(hinfo.pmi_section_table[18].psh_virtual_address == 0x000b3000);
    assert(hinfo.pmi_section_table[18].psh_size_of_raw_data == 14848);
    assert(hinfo.pmi_section_table[18].psh_pointer_to_raw_data == 0x000a7400);
    assert(hinfo.pmi_section_table[18].psh_pointer_to_relocations == 0);
    assert(hinfo.pmi_section_table[18].psh_pointer_to_linenumbers == 0);
    assert(hinfo.pmi_section_table[18].psh_number_of_relocations == 0);
    assert(hinfo.pmi_section_table[18].psh_number_of_linenumbers == 0);
    assert(hinfo.pmi_section_table[18].psh_characteristics == (PE_IMAGE_SCN_MEM_READ | PE_IMAGE_SCN_MEM_DISCARDABLE | 0x00100000 | PE_IMAGE_SCN_CNT_INITIALIZED_DATA));
}


static void
test_valid_pe64_msvc_exe_image__all_headers(void)
{
    const uint8_t bytes[512 * 2] =
    {
        /*** MZ header - 248 bytes ***/

        0x4d, 0x5a, 0x90, 0x00, 0x03, 0x00, 0x00, 0x00,
        0x04, 0x00, 0x00, 0x00, 0xff, 0xff, 0x00, 0x00,
        0xb8, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x40, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0xf8, 0x00, 0x00, 0x00,
        0x0e, 0x1f, 0xba, 0x0e, 0x00, 0xb4, 0x09, 0xcd,
        0x21, 0xb8, 0x01, 0x4c, 0xcd, 0x21, 0x54, 0x68,
        0x69, 0x73, 0x20, 0x70, 0x72, 0x6f, 0x67, 0x72,
        0x61, 0x6d, 0x20, 0x63, 0x61, 0x6e, 0x6e, 0x6f,
        0x74, 0x20, 0x62, 0x65, 0x20, 0x72, 0x75, 0x6e,
        0x20, 0x69, 0x6e, 0x20, 0x44, 0x4f, 0x53, 0x20,
        0x6d, 0x6f, 0x64, 0x65, 0x2e, 0x0d, 0x0d, 0x0a,
        0x24, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0xc9, 0x20, 0xac, 0x15, 0x8d, 0x41, 0xc2, 0x46,
        0x8d, 0x41, 0xc2, 0x46, 0x8d, 0x41, 0xc2, 0x46,
        0x75, 0x31, 0xc3, 0x47, 0x8e, 0x41, 0xc2, 0x46,
        0x75, 0x31, 0xc7, 0x47, 0x9a, 0x41, 0xc2, 0x46,
        0x75, 0x31, 0xc6, 0x47, 0x87, 0x41, 0xc2, 0x46,
        0x75, 0x31, 0xc1, 0x47, 0x89, 0x41, 0xc2, 0x46,
        0xd6, 0x29, 0xc3, 0x47, 0x89, 0x41, 0xc2, 0x46,
        0x8d, 0x41, 0xc3, 0x46, 0xcb, 0x41, 0xc2, 0x46,
        0x35, 0x30, 0xc6, 0x47, 0x8f, 0x41, 0xc2, 0x46,
        0x35, 0x30, 0x3d, 0x46, 0x8c, 0x41, 0xc2, 0x46,
        0x35, 0x30, 0xc0, 0x47, 0x8c, 0x41, 0xc2, 0x46,
        0x52, 0x69, 0x63, 0x68, 0x8d, 0x41, 0xc2, 0x46,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,

        /*** PE signature + COFF header - 4 + 20 bytes ***/
        0x50, 0x45, 0x00, 0x00, 0x64, 0x86, 0x08, 0x00,
        0x47, 0xdf, 0x8f, 0x5f, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0xf0, 0x00, 0x22, 0x00,

        /*** Optional header - 240 bytes ***/

        /* Common fields */
        0x0b, 0x02, 0x0e, 0x1b, 0x00, 0x1c, 0x01, 0x00,
        0x00, 0xae, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x14, 0x10, 0x00, 0x00, 0x00, 0x10, 0x00, 0x00,

        /* Windows-specific fields */
        0x00, 0x00, 0x00, 0x40, 0x01, 0x00, 0x00, 0x00,
        0x00, 0x10, 0x00, 0x00, 0x00, 0x02, 0x00, 0x00,
        0x06, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x06, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x10, 0x03, 0x00, 0x00, 0x04, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x03, 0x00, 0x60, 0x81,
        0x00, 0x00, 0x10, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x10, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x10, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x10, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x10, 0x00, 0x00, 0x00,

        /* Data directories */
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0xa0, 0xd3, 0x02, 0x00, 0x50, 0x00, 0x00, 0x00,
        0x00, 0xf0, 0x02, 0x00, 0x3c, 0x04, 0x00, 0x00,
        0x00, 0xc0, 0x02, 0x00, 0xf4, 0x05, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x03, 0x00, 0xf4, 0x00, 0x00, 0x00,
        0xb8, 0x58, 0x01, 0x00, 0x38, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0xf0, 0x58, 0x01, 0x00, 0x30, 0x01, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0xd0, 0x02, 0x00, 0xa0, 0x03, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,

        /*** Section table - 320 bytes ***/

        0x2e, 0x74, 0x65, 0x78, 0x74, 0x00, 0x00, 0x00,
        0x7f, 0x1a, 0x01, 0x00, 0x00, 0x10, 0x00, 0x00,
        0x00, 0x1c, 0x01, 0x00, 0x00, 0x04, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x20, 0x00, 0x00, 0x60,

        0x2e, 0x72, 0x64, 0x61, 0x74, 0x61, 0x00, 0x00,
        0x24, 0x3d, 0x00, 0x00, 0x00, 0x30, 0x01, 0x00,
        0x00, 0x3e, 0x00, 0x00, 0x00, 0x20, 0x01, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x40, 0x00, 0x00, 0x40,

        0x2e, 0x64, 0x61, 0x74, 0x61, 0x00, 0x00, 0x00,
        0xa1, 0x4a, 0x01, 0x00, 0x00, 0x70, 0x01, 0x00,
        0x00, 0x44, 0x01, 0x00, 0x00, 0x5e, 0x01, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x40, 0x00, 0x00, 0xc0,

        0x2e, 0x70, 0x64, 0x61, 0x74, 0x61, 0x00, 0x00,
        0xb0, 0x07, 0x00, 0x00, 0x00, 0xc0, 0x02, 0x00,
        0x00, 0x08, 0x00, 0x00, 0x00, 0xa2, 0x02, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x40, 0x00, 0x00, 0x40,

        0x2e, 0x69, 0x64, 0x61, 0x74, 0x61, 0x00, 0x00,
        0xcb, 0x0e, 0x00, 0x00, 0x00, 0xd0, 0x02, 0x00,
        0x00, 0x10, 0x00, 0x00, 0x00, 0xaa, 0x02, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x40, 0x00, 0x00, 0x40,

        0x2e, 0x30, 0x30, 0x63, 0x66, 0x67, 0x00, 0x00,
        0x51, 0x01, 0x00, 0x00, 0x00, 0xe0, 0x02, 0x00,
        0x00, 0x02, 0x00, 0x00, 0x00, 0xba, 0x02, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x40, 0x00, 0x00, 0x40,

        0x2e, 0x72, 0x73, 0x72, 0x63, 0x00, 0x00, 0x00,
        0x3c, 0x04, 0x00, 0x00, 0x00, 0xf0, 0x02, 0x00,
        0x00, 0x06, 0x00, 0x00, 0x00, 0xbc, 0x02, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x40, 0x00, 0x00, 0x40,

        0x2e, 0x72, 0x65, 0x6c, 0x6f, 0x63, 0x00, 0x00,
        0x72, 0x03, 0x00, 0x00, 0x00, 0x00, 0x03, 0x00,
        0x00, 0x04, 0x00, 0x00, 0x00, 0xc2, 0x02, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x40, 0x00, 0x00, 0x42,
    };

    struct pe_header_info   hinfo;
    xwb_err_t               err;
    size_t                  len;

    len = 832;
    err = xwb_parse_pe_headers(bytes, &len, 512 * 2, &hinfo);
    assert(err == XWB_E_SUCCESS);

    assert(hinfo.pmi_coff_file_header_off == 248 + 4);

    /* COFF file header */
    assert(hinfo.pmi_coff_file_header.cfh_machine == PE_IMAGE_FILE_MACHINE_AMD64);
    assert(hinfo.pmi_coff_file_header.cfh_num_sections == 8);
    assert(hinfo.pmi_coff_file_header.cfh_time_date_stamp == 0x5f8fdf47);
    assert(hinfo.pmi_coff_file_header.cfh_pointer_to_symbol_table == 0);
    assert(hinfo.pmi_coff_file_header.cfh_number_of_symbols == 0);
    assert(hinfo.pmi_coff_file_header.cfh_size_of_optional_header == 240);
    assert(hinfo.pmi_coff_file_header.cfh_characteristics == (PE_IMAGE_FILE_EXECUTABLE_IMAGE | PE_IMAGE_FILE_LARGE_ADDRESS_AWARE));

    assert(hinfo.pmi_has_optional_header == 1);
    assert(hinfo.pmi_optional_header_off == 248 + 4 + 20);

    /* Optional header - common fields */
    assert(hinfo.pmi_optional_header.poh_magic == PE_IMAGE_OPT_HDR64_MAGIC);
    assert(hinfo.pmi_optional_header.poh_major_linker_version == 14);
    assert(hinfo.pmi_optional_header.poh_minor_linker_version == 27);
    assert(hinfo.pmi_optional_header.poh_size_of_code == 72704);
    assert(hinfo.pmi_optional_header.poh_size_of_initialized_data == 110080);
    assert(hinfo.pmi_optional_header.poh_size_of_uninitialized_data == 0);
    assert(hinfo.pmi_optional_header.poh_address_of_entrypoint == 0x00001014);
    assert(hinfo.pmi_optional_header.poh_base_of_code == 0x00001000);
    assert(hinfo.pmi_optional_header.poh_base_of_data == 0);

    /* Optional header - Windows-specific fields */
    assert(hinfo.pmi_optional_header.poh_image_base == 0x0000000140000000ULL);
    assert(hinfo.pmi_optional_header.poh_section_alignment == 4096);
    assert(hinfo.pmi_optional_header.poh_file_alignment == 512);
    assert(hinfo.pmi_optional_header.poh_os_version_major == 6);
    assert(hinfo.pmi_optional_header.poh_os_version_minor == 0);
    assert(hinfo.pmi_optional_header.poh_image_version_major == 0);
    assert(hinfo.pmi_optional_header.poh_image_version_minor == 0);
    assert(hinfo.pmi_optional_header.poh_subsystem_version_major == 6);
    assert(hinfo.pmi_optional_header.poh_subsystem_version_minor == 0);
    assert(hinfo.pmi_optional_header.poh_win32_version_value == 0);
    assert(hinfo.pmi_optional_header.poh_size_of_image == 200704);
    assert(hinfo.pmi_optional_header.poh_size_of_headers == 1024);
    assert(hinfo.pmi_optional_header.poh_checksum == 0);
    assert(hinfo.pmi_optional_header.poh_subsystem == 3);
    assert(hinfo.pmi_optional_header.poh_dll_characteristics == (PE_IMAGE_DLLCHARACTERISTICS_TERMINAL_SERVER_AWARE | PE_IMAGE_DLL_CHARACTERISTICS_NX_COMPAT | PE_IMAGE_DLL_CHARACTERISTICS_DYNAMIC_BASE | PE_IMAGE_DLLCHARACTERISTICS_HIGH_ENTROPY_VA));
    assert(hinfo.pmi_optional_header.poh_size_of_stack_reserve == 1048576);
    assert(hinfo.pmi_optional_header.poh_size_of_stack_commit == 4096);
    assert(hinfo.pmi_optional_header.poh_size_of_heap_reserve == 1048576);
    assert(hinfo.pmi_optional_header.poh_size_of_heap_commit == 4096);
    assert(hinfo.pmi_optional_header.poh_loaderflags == 0);
    assert(hinfo.pmi_optional_header.poh_num_datadir_entries == 16);

    /* Optional header - data directories */
    assert(hinfo.pmi_optional_header.poh_datadir_entries[PE_IMAGE_OPT_DD_OFF_EXPORT].pde_virtual_address == 0);
    assert(hinfo.pmi_optional_header.poh_datadir_entries[PE_IMAGE_OPT_DD_OFF_EXPORT].pde_size == 0);
    assert(hinfo.pmi_optional_header.poh_datadir_entries[PE_IMAGE_OPT_DD_OFF_IMPORT].pde_virtual_address == 0x0002d3a0);
    assert(hinfo.pmi_optional_header.poh_datadir_entries[PE_IMAGE_OPT_DD_OFF_IMPORT].pde_size == 80);
    assert(hinfo.pmi_optional_header.poh_datadir_entries[PE_IMAGE_OPT_DD_OFF_RESOURCE].pde_virtual_address == 0x0002f000);
    assert(hinfo.pmi_optional_header.poh_datadir_entries[PE_IMAGE_OPT_DD_OFF_RESOURCE].pde_size == 1084);
    assert(hinfo.pmi_optional_header.poh_datadir_entries[PE_IMAGE_OPT_DD_OFF_EXCEPTION].pde_virtual_address == 0x0002c000);
    assert(hinfo.pmi_optional_header.poh_datadir_entries[PE_IMAGE_OPT_DD_OFF_EXCEPTION].pde_size == 1524);
    assert(hinfo.pmi_optional_header.poh_datadir_entries[PE_IMAGE_OPT_DD_OFF_CERTIFICATE].pde_virtual_address == 0);
    assert(hinfo.pmi_optional_header.poh_datadir_entries[PE_IMAGE_OPT_DD_OFF_CERTIFICATE].pde_size == 0);
    assert(hinfo.pmi_optional_header.poh_datadir_entries[PE_IMAGE_OPT_DD_OFF_RELOCATION].pde_virtual_address == 0x00030000);
    assert(hinfo.pmi_optional_header.poh_datadir_entries[PE_IMAGE_OPT_DD_OFF_RELOCATION].pde_size == 244);
    assert(hinfo.pmi_optional_header.poh_datadir_entries[PE_IMAGE_OPT_DD_OFF_DEBUG].pde_virtual_address == 0x000158b8);
    assert(hinfo.pmi_optional_header.poh_datadir_entries[PE_IMAGE_OPT_DD_OFF_DEBUG].pde_size == 56);
    assert(hinfo.pmi_optional_header.poh_datadir_entries[PE_IMAGE_OPT_DD_OFF_ARCH].pde_virtual_address == 0);
    assert(hinfo.pmi_optional_header.poh_datadir_entries[PE_IMAGE_OPT_DD_OFF_ARCH].pde_size == 0);
    assert(hinfo.pmi_optional_header.poh_datadir_entries[PE_IMAGE_OPT_DD_OFF_GLOBALPTR].pde_virtual_address == 0);
    assert(hinfo.pmi_optional_header.poh_datadir_entries[PE_IMAGE_OPT_DD_OFF_GLOBALPTR].pde_size == 0);
    assert(hinfo.pmi_optional_header.poh_datadir_entries[PE_IMAGE_OPT_DD_OFF_TLS].pde_virtual_address == 0);
    assert(hinfo.pmi_optional_header.poh_datadir_entries[PE_IMAGE_OPT_DD_OFF_TLS].pde_size == 0);
    assert(hinfo.pmi_optional_header.poh_datadir_entries[PE_IMAGE_OPT_DD_OFF_LOADCONFIG].pde_virtual_address == 0x000158f0);
    assert(hinfo.pmi_optional_header.poh_datadir_entries[PE_IMAGE_OPT_DD_OFF_LOADCONFIG].pde_size == 304);
    assert(hinfo.pmi_optional_header.poh_datadir_entries[PE_IMAGE_OPT_DD_OFF_BOUNDIMPORT].pde_virtual_address == 0);
    assert(hinfo.pmi_optional_header.poh_datadir_entries[PE_IMAGE_OPT_DD_OFF_BOUNDIMPORT].pde_size == 0);
    assert(hinfo.pmi_optional_header.poh_datadir_entries[PE_IMAGE_OPT_DD_OFF_IAT].pde_virtual_address == 0x0002d000);
    assert(hinfo.pmi_optional_header.poh_datadir_entries[PE_IMAGE_OPT_DD_OFF_IAT].pde_size == 928);
    assert(hinfo.pmi_optional_header.poh_datadir_entries[PE_IMAGE_OPT_DD_OFF_DELAYIMPORT].pde_virtual_address == 0);
    assert(hinfo.pmi_optional_header.poh_datadir_entries[PE_IMAGE_OPT_DD_OFF_DELAYIMPORT].pde_size == 0);
    assert(hinfo.pmi_optional_header.poh_datadir_entries[PE_IMAGE_OPT_DD_OFF_CLRRUNTIME].pde_virtual_address == 0);
    assert(hinfo.pmi_optional_header.poh_datadir_entries[PE_IMAGE_OPT_DD_OFF_CLRRUNTIME].pde_size == 0);
    assert(hinfo.pmi_optional_header.poh_datadir_entries[PE_IMAGE_OPT_DD_OFF_RESERVED].pde_virtual_address == 0);
    assert(hinfo.pmi_optional_header.poh_datadir_entries[PE_IMAGE_OPT_DD_OFF_RESERVED].pde_size == 0);

    assert(hinfo.pmi_section_table_off == 248 + 4 + 20 + 240);

    /* Section table */

    assert(strcmp(hinfo.pmi_section_table[0].psh_name, ".text") == 0);
    assert(hinfo.pmi_section_table[0].psh_virtual_size == 72319);
    assert(hinfo.pmi_section_table[0].psh_virtual_address == 0x00001000);
    assert(hinfo.pmi_section_table[0].psh_size_of_raw_data == 72704);
    assert(hinfo.pmi_section_table[0].psh_pointer_to_raw_data == 0x00000400);
    assert(hinfo.pmi_section_table[0].psh_pointer_to_relocations == 0);
    assert(hinfo.pmi_section_table[0].psh_pointer_to_linenumbers == 0);
    assert(hinfo.pmi_section_table[0].psh_number_of_relocations == 0);
    assert(hinfo.pmi_section_table[0].psh_number_of_linenumbers == 0);
    assert(hinfo.pmi_section_table[0].psh_characteristics == (PE_IMAGE_SCN_MEM_READ | PE_IMAGE_SCN_MEM_EXECUTE | PE_IMAGE_SCN_CNT_CODE));

    assert(strcmp(hinfo.pmi_section_table[1].psh_name, ".rdata") == 0);
    assert(hinfo.pmi_section_table[1].psh_virtual_size == 15652);
    assert(hinfo.pmi_section_table[1].psh_virtual_address == 0x00013000);
    assert(hinfo.pmi_section_table[1].psh_size_of_raw_data == 15872);
    assert(hinfo.pmi_section_table[1].psh_pointer_to_raw_data == 0x00012000);
    assert(hinfo.pmi_section_table[1].psh_pointer_to_relocations == 0);
    assert(hinfo.pmi_section_table[1].psh_pointer_to_linenumbers == 0);
    assert(hinfo.pmi_section_table[1].psh_number_of_relocations == 0);
    assert(hinfo.pmi_section_table[1].psh_number_of_linenumbers == 0);
    assert(hinfo.pmi_section_table[1].psh_characteristics == (PE_IMAGE_SCN_MEM_READ | PE_IMAGE_SCN_CNT_INITIALIZED_DATA));

    assert(strcmp(hinfo.pmi_section_table[2].psh_name, ".data") == 0);
    assert(hinfo.pmi_section_table[2].psh_virtual_size == 84641);
    assert(hinfo.pmi_section_table[2].psh_virtual_address == 0x00017000);
    assert(hinfo.pmi_section_table[2].psh_size_of_raw_data == 82944);
    assert(hinfo.pmi_section_table[2].psh_pointer_to_raw_data == 0x00015e00);
    assert(hinfo.pmi_section_table[2].psh_pointer_to_relocations == 0);
    assert(hinfo.pmi_section_table[2].psh_pointer_to_linenumbers == 0);
    assert(hinfo.pmi_section_table[2].psh_number_of_relocations == 0);
    assert(hinfo.pmi_section_table[2].psh_number_of_linenumbers == 0);
    assert(hinfo.pmi_section_table[2].psh_characteristics == (PE_IMAGE_SCN_MEM_WRITE | PE_IMAGE_SCN_MEM_READ | PE_IMAGE_SCN_CNT_INITIALIZED_DATA));

    assert(strcmp(hinfo.pmi_section_table[3].psh_name, ".pdata") == 0);
    assert(hinfo.pmi_section_table[3].psh_virtual_size == 1968);
    assert(hinfo.pmi_section_table[3].psh_virtual_address == 0x0002c000);
    assert(hinfo.pmi_section_table[3].psh_size_of_raw_data == 2048);
    assert(hinfo.pmi_section_table[3].psh_pointer_to_raw_data == 0x0002a200);
    assert(hinfo.pmi_section_table[3].psh_pointer_to_relocations == 0);
    assert(hinfo.pmi_section_table[3].psh_pointer_to_linenumbers == 0);
    assert(hinfo.pmi_section_table[3].psh_number_of_relocations == 0);
    assert(hinfo.pmi_section_table[3].psh_number_of_linenumbers == 0);
    assert(hinfo.pmi_section_table[3].psh_characteristics == (PE_IMAGE_SCN_MEM_READ | PE_IMAGE_SCN_CNT_INITIALIZED_DATA));

    assert(strcmp(hinfo.pmi_section_table[4].psh_name, ".idata") == 0);
    assert(hinfo.pmi_section_table[4].psh_virtual_size == 3787);
    assert(hinfo.pmi_section_table[4].psh_virtual_address == 0x0002d000);
    assert(hinfo.pmi_section_table[4].psh_size_of_raw_data == 4096);
    assert(hinfo.pmi_section_table[4].psh_pointer_to_raw_data == 0x0002aa00);
    assert(hinfo.pmi_section_table[4].psh_pointer_to_relocations == 0);
    assert(hinfo.pmi_section_table[4].psh_pointer_to_linenumbers == 0);
    assert(hinfo.pmi_section_table[4].psh_number_of_relocations == 0);
    assert(hinfo.pmi_section_table[4].psh_number_of_linenumbers == 0);
    assert(hinfo.pmi_section_table[4].psh_characteristics == (PE_IMAGE_SCN_MEM_READ | PE_IMAGE_SCN_CNT_INITIALIZED_DATA));

    assert(strcmp(hinfo.pmi_section_table[5].psh_name, ".00cfg") == 0);
    assert(hinfo.pmi_section_table[5].psh_virtual_size == 337);
    assert(hinfo.pmi_section_table[5].psh_virtual_address == 0x0002e000);
    assert(hinfo.pmi_section_table[5].psh_size_of_raw_data == 512);
    assert(hinfo.pmi_section_table[5].psh_pointer_to_raw_data == 0x0002ba00);
    assert(hinfo.pmi_section_table[5].psh_pointer_to_relocations == 0);
    assert(hinfo.pmi_section_table[5].psh_pointer_to_linenumbers == 0);
    assert(hinfo.pmi_section_table[5].psh_number_of_relocations == 0);
    assert(hinfo.pmi_section_table[5].psh_number_of_linenumbers == 0);
    assert(hinfo.pmi_section_table[5].psh_characteristics == (PE_IMAGE_SCN_MEM_READ | PE_IMAGE_SCN_CNT_INITIALIZED_DATA));

    assert(strcmp(hinfo.pmi_section_table[6].psh_name, ".rsrc") == 0);
    assert(hinfo.pmi_section_table[6].psh_virtual_size == 1084);
    assert(hinfo.pmi_section_table[6].psh_virtual_address == 0x0002f000);
    assert(hinfo.pmi_section_table[6].psh_size_of_raw_data == 1536);
    assert(hinfo.pmi_section_table[6].psh_pointer_to_raw_data == 0x0002bc00);
    assert(hinfo.pmi_section_table[6].psh_pointer_to_relocations == 0);
    assert(hinfo.pmi_section_table[6].psh_pointer_to_linenumbers == 0);
    assert(hinfo.pmi_section_table[6].psh_number_of_relocations == 0);
    assert(hinfo.pmi_section_table[6].psh_number_of_linenumbers == 0);
    assert(hinfo.pmi_section_table[6].psh_characteristics == (PE_IMAGE_SCN_MEM_READ | PE_IMAGE_SCN_CNT_INITIALIZED_DATA));

    assert(strcmp(hinfo.pmi_section_table[7].psh_name, ".reloc") == 0);
    assert(hinfo.pmi_section_table[7].psh_virtual_size == 882);
    assert(hinfo.pmi_section_table[7].psh_virtual_address == 0x00030000);
    assert(hinfo.pmi_section_table[7].psh_size_of_raw_data == 1024);
    assert(hinfo.pmi_section_table[7].psh_pointer_to_raw_data == 0x0002c200);
    assert(hinfo.pmi_section_table[7].psh_pointer_to_relocations == 0);
    assert(hinfo.pmi_section_table[7].psh_pointer_to_linenumbers == 0);
    assert(hinfo.pmi_section_table[7].psh_number_of_relocations == 0);
    assert(hinfo.pmi_section_table[7].psh_number_of_linenumbers == 0);
    assert(hinfo.pmi_section_table[7].psh_characteristics == (PE_IMAGE_SCN_MEM_READ | PE_IMAGE_SCN_MEM_DISCARDABLE | PE_IMAGE_SCN_CNT_INITIALIZED_DATA));
}


int
main(void)
{
    test_parser_needs_at_least_twenty_bytes();
    test_invalid_object_file__missing_section_headers();
    test_valid_object_file__no_section_headers();
    test_valid_object_file__no_section_headers_and_file_size_less_than_sixtyfour_bytes();
    test_valid_object_file__one_section_header_and_file_size_less_than_sixtyfour_bytes();
    test_valid_object_file__one_section_header_and_file_size_equal_to_sixtyfour_bytes();
    test_invalid_object_file__more_than_one_section_header_and_file_size_equal_to_sixtyfour_bytes__missing_section_headers();
    test_invalid_object_file__more_than_one_section_header_and_file_size_equal_to_sixtyfour_bytes();
    test_valid_object_file__file_size_equal_to_sixtyfour_bytes_and_possible_pe_signature_offset();
    test_valid_object_file__buffer_without_all_section_headers();
    test_invalid_object_file__too_many_sections();
    test_valid_pe64_image__no_pe_signature();
    test_valid_pe64_image__no_coff_header();
    test_invalid_pe64_image__no_coff_header();
    test_valid_pe64_image__no_section_headers();
    test_invalid_pe64_image__optional_header_size_is_zero();
    test_invalid_pe64_image__optional_header_size_is_smaller_than_minimum_size();
    test_valid_pe64_image__not_enough_optional_header_bytes();
    test_valid_pe64_mingw_exe_image__all_headers();
    test_valid_pe64_msvc_exe_image__all_headers();

    return 0;
}
