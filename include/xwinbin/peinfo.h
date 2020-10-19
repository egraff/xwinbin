#ifndef X_WIN_BIN_PEINFO_H
#define X_WIN_BIN_PEINFO_H


#include <xwinbin/types.h>
#include <xwinbin/err.h>
#include <xwinbin/pe_enum.h>
#include <stdint.h>
#include <stddef.h>


/* Limit for number of sections (see 2.3) */
#define PE_MAX_NUM_SECTIONS 96


struct coff_file_header
{
    uint16_t cfh_machine;                       /**< 2.3.1 Machine Types */
    uint16_t cfh_num_sections;                  /**< Number of sections in section table */
    uint32_t cfh_time_date_stamp;               /**< When file was created as low 32 bits of time_t */
    uint32_t cfh_pointer_to_symbol_table;       /**< File offset of COFF symbol table (deprecated for images) */
    uint32_t cfh_number_of_symbols;             /**< Number of entries in symbol table (deprecated for images) */
    uint16_t cfh_size_of_optional_header;       /**< Size of optional header (including data directories) */
    uint16_t cfh_characteristics;               /**< Flags that indicate the attributes of the file (see 3.3.2) */
};


struct pe_datadir_entry {
    xwb_rva_t   pde_virtual_address;  /**< RVA (relative virtual address), relative to base of image when table is loaded */
    uint32_t    pde_size;             /**< Size in bytes */
};


struct pe_opt_header
{
    uint16_t                poh_magic;
    uint8_t                 poh_major_linker_version;
    uint8_t                 poh_minor_linker_version;
    uint32_t                poh_size_of_code;                  /**< Total size of all code (text) sections */
    uint32_t                poh_size_of_initialized_data;      /**< Total size of all initialized data sections */
    uint32_t                poh_size_of_uninitialized_data;    /**< Total size of all BSS sections */
    xwb_rva_t               poh_address_of_entrypoint;         /**< Address of entry point relative to image base in memory */
    xwb_rva_t               poh_base_of_code;                  /**< Address of beginning-of-code section relative to image base in memory */
    xwb_rva_t               poh_base_of_data;                  /**< Address of beginning-of-data section relative to image base in memory */

    /* 2.4.2 Windows-Specific Fields */
    uint64_t                poh_image_base;
    uint32_t                poh_section_alignment;
    uint32_t                poh_file_alignment;
    uint16_t                poh_os_version_major;
    uint16_t                poh_os_version_minor;
    uint16_t                poh_image_version_major;
    uint16_t                poh_image_version_minor;
    uint16_t                poh_subsystem_version_major;
    uint16_t                poh_subsystem_version_minor;
    uint32_t                poh_win32_version_value;
    uint32_t                poh_size_of_image;
    uint32_t                poh_size_of_headers;               /**< The combined size of the MS-DOS stub, PE header, and section headers rounded up to a multiple of the file alignment. */
    uint32_t                poh_checksum;
    uint16_t                poh_subsystem;
    uint16_t                poh_dll_characteristics;
    uint64_t                poh_size_of_stack_reserve;
    uint64_t                poh_size_of_stack_commit;
    uint64_t                poh_size_of_heap_reserve;
    uint64_t                poh_size_of_heap_commit;
    uint32_t                poh_loaderflags;
    uint32_t                poh_num_datadir_entries;
    struct pe_datadir_entry poh_datadir_entries[PE_IMAGE_OPT_DD_MAXNUM];
};


struct pe_section_header
{
    char     psh_name[9];
    uint32_t psh_virtual_size;
    uint32_t psh_virtual_address;
    uint32_t psh_size_of_raw_data;
    uint32_t psh_pointer_to_raw_data;
    uint32_t psh_pointer_to_relocations;  /**< 0 for executable images */
    uint32_t psh_pointer_to_linenumbers;  /**< Deprecated for images */
    uint16_t psh_number_of_relocations;   /**< 0 for executable images */
    uint16_t psh_number_of_linenumbers;   /**< Deprecated for images */
    uint32_t psh_characteristics;         /**< 3.1 Section Flags */
};


struct pe_header_info
{
    xwb_off_t                   pmi_coff_file_header_off;
    struct coff_file_header     pmi_coff_file_header;
    int                         pmi_has_optional_header;
    xwb_off_t                   pmi_optional_header_off;
    struct pe_opt_header        pmi_optional_header;
    xwb_off_t                   pmi_section_table_off;
    struct pe_section_header    pmi_section_table[PE_MAX_NUM_SECTIONS];
};


#endif /* X_WIN_BIN_PEINFO_H */
