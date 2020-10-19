#ifndef X_WIN_BIN_PE_ENUM_H
#define X_WIN_BIN_PE_ENUM_H


/* 3.3.1 Machine Types */
enum
{
    PE_IMAGE_FILE_MACHINE_UNKNOWN    = 0x0000, /**< Applicable to any machine type */
    PE_IMAGE_FILE_MACHINE_AM33       = 0x01d3, /**< Matsushita AM33 */
    PE_IMAGE_FILE_MACHINE_AMD64      = 0x8664, /**< x64 */
    PE_IMAGE_FILE_MACHINE_ARM        = 0x01c0, /**< ARM little endian */
    PE_IMAGE_FILE_MACHINE_ARM64      = 0xaa64, /**< ARM64 little endian */
    PE_IMAGE_FILE_MACHINE_ARMV7      = 0x01c4, /**< ARMv7 (or higher) Thumb mode only */
    PE_IMAGE_FILE_MACHINE_ARMNT      = 0x01c4, /**< ARM Thumb-2 little endian */
    PE_IMAGE_FILE_MACHINE_EBC        = 0x0ebc, /**< EFI byte code */
    PE_IMAGE_FILE_MACHINE_I386       = 0x014c, /**< Intel 386 compatible */
    PE_IMAGE_FILE_MACHINE_IA64       = 0x0200, /**< Intel Itanium */
    PE_IMAGE_FILE_MACHINE_M32R       = 0x9041, /**< Mitsubishi M32R little endian */
    PE_IMAGE_FILE_MACHINE_MIPS16     = 0x0266, /**< MIPS16 */
    PE_IMAGE_FILE_MACHINE_MIPSFPU    = 0x0366, /**< MIPS with FPU */
    PE_IMAGE_FILE_MACHINE_MIPSFPU16  = 0x0466, /**< MIPS16 with FPU */
    PE_IMAGE_FILE_MACHINE_POWERPC    = 0x01f0, /**< Power PC little endian */
    PE_IMAGE_FILE_MACHINE_POWERPCFP  = 0x01f1, /**< Power PC with floating point support */
    PE_IMAGE_FILE_MACHINE_R4000      = 0x0166, /**< MIPS little endian */
    PE_IMAGE_FILE_MACHINE_RISCV32    = 0x5032, /**< RISC-V 32-bit address space */
    PE_IMAGE_FILE_MACHINE_RISCV64    = 0x5064, /**< RISC-V 64-bit address space */
    PE_IMAGE_FILE_MACHINE_RISCV128   = 0x5128, /**< RISC-V 128-bit address space */
    PE_IMAGE_FILE_MACHINE_SH3        = 0x01a2, /**< Hitachi SH3 */
    PE_IMAGE_FILE_MACHINE_SH3DSP     = 0x01a3, /**< Hitachi SH3 DSP */
    PE_IMAGE_FILE_MACHINE_SH4        = 0x01a6, /**< Hitachi SH4 */
    PE_IMAGE_FILE_MACHINE_SH5        = 0x01a8, /**< Hitachi SH5 */
    PE_IMAGE_FILE_MACHINE_THUMB      = 0x01c2, /**< ARM or Thumb ("interworking") */
    PE_IMAGE_FILE_MACHINE_WCEMIPSV2  = 0x0169  /**< MIPS little-endian WCE v2 */
};


/* 3.3.2 Characteristics */
enum
{
    PE_IMAGE_FILE_RELOCS_STRIPPED          = (1 <<  0), /**< Relocation information was stripped from the file. Image _must_ be loaded at preferred base address */
    PE_IMAGE_FILE_EXECUTABLE_IMAGE         = (1 <<  1), /**< Image is valid executable (linker error if not set) */
    PE_IMAGE_FILE_LINE_NUMS_STRIPPED       = (1 <<  2), /**< COFF line numbers have been stripped from the file */
    PE_IMAGE_FILE_LOCAL_SYMS_STRIPPED      = (1 <<  3), /**< COFF symbol table entries have been stripped from the file */
    PE_IMAGE_FILE_AGGRESSIVE_WS_TRIM       = (1 <<  4), /**< Aggressively trim the working set. Obsolete */
    PE_IMAGE_FILE_LARGE_ADDRESS_AWARE      = (1 <<  5), /**< Application can handle > 2GB addresses */
    PE_IMAGE_FILE_RESERVED                 = (1 <<  6), /**< Reserved for future use */
    PE_IMAGE_FILE_BYTES_REVERSED_LO        = (1 <<  7), /**< The bytes of the word are reversed. Obsolete */
    PE_IMAGE_FILE_32BIT_MACHINE            = (1 <<  8), /**< Machine is based on 32-bit-word architecture */
    PE_IMAGE_FILE_DEBUG_STRIPPED           = (1 <<  9), /**< Debugging information has been removed from image */
    PE_IMAGE_FILE_REMOVABLE_RUN_FROM_SWAP  = (1 << 10), /**< If image is on removable media, fully load it and copy to swap file */
    PE_IMAGE_FILE_NET_RUN_FROM_SWAP        = (1 << 11), /**< If image is on network media, fully load it and copy to swap file */
    PE_IMAGE_FILE_SYSTEM                   = (1 << 12), /**< Image is system file, not user program */
    PE_IMAGE_FILE_DLL                      = (1 << 13), /**< Image is DLL */
    PE_IMAGE_FILE_UP_SYSTEM_ONLY           = (1 << 14), /**< File should only be run on uniprocessor machine */
    PE_IMAGE_FILE_BYTES_REVERSED_HI        = (1 << 15)  /**< The bytes of the word are reversed. Obsolete */
};


/* 3.4 Optional Header */
enum
{
    PE_IMAGE_OPT_HDR32_MAGIC = 0x10b,
    PE_IMAGE_OPT_HDR64_MAGIC = 0x20b
};


/* 3.4.2 Windows Subsystem */
enum
{
    PE_IMAGE_SUBSYSTEM_UNKNOWN                  = 0,
    PE_IMAGE_SUBSYSTEM_NATIVE                   = 1,
    PE_IMAGE_SUBSYSTEM_WINDOWS_GUI              = 2,
    PE_IMAGE_SUBSYSTEM_WINDOWS_CUI              = 3,
    PE_IMAGE_SUBSYSTEM_OS2_CUI                  = 5,
    PE_IMAGE_SUBSYSTEM_POSIX_CUI                = 7,
    PE_IMAGE_SUBSYSTEM_NATIVE_WINDOWS           = 8,
    PE_IMAGE_SUBSYSTEM_WINDOWS_CE_GUI           = 9,
    PE_IMAGE_SUBSYSTEM_EFI_APPLICATION          = 10,
    PE_IMAGE_SUBSYSTEM_EFI_BOOT_SERVICE_DRIVER  = 11,
    PE_IMAGE_SUBSYSTEM_EFI_RUNTIME_DRIVER       = 12,
    PE_IMAGE_SUBSYSTEM_EFI_ROM                  = 13,
    PE_IMAGE_SUBSYSTEM_XBOX                     = 14,
    PE_IMAGE_SUBSYSTEM_WINDOWS_BOOT_APPLICATION = 16
};


/* 3.4.2 DLL Characteristics */
enum
{
    PE_IMAGE_DLLCHARACTERISTICS_HIGH_ENTROPY_VA         = 0x0020, /**< Image can handle a high entropy 64-bit virtual address space. */
    PE_IMAGE_DLL_CHARACTERISTICS_DYNAMIC_BASE           = 0x0040, /**< DLL can be relocated at load time. */
    PE_IMAGE_DLL_CHARACTERISTICS_FORCE_INTEGRITY        = 0x0080, /**< Code Integrity checks are enforced. */
    PE_IMAGE_DLL_CHARACTERISTICS_NX_COMPAT              = 0x0100, /**< Image is NX compatible. */
    PE_IMAGE_DLLCHARACTERISTICS_NO_ISOLATION            = 0x0200, /**< Isolation aware, but do not isolate the image. */
    PE_IMAGE_DLLCHARACTERISTICS_NO_SEH                  = 0x0400, /**< Does not use structured exception handling. */
    PE_IMAGE_DLLCHARACTERISTICS_NO_BIND                 = 0x0800, /**< Do not bind the image. */
    PE_IMAGE_DLLCHARACTERISTICS_APPCONTAINER            = 0x1000, /**< Image must execute in an AppContainer. */
    PE_IMAGE_DLLCHARACTERISTICS_WDM_DRIVER              = 0x2000, /**< A WDM driver. */
    PE_IMAGE_DLLCHARACTERISTICS_GUARD_CF                = 0x4000, /**< Image supports Control Flow Guard. */
    PE_IMAGE_DLLCHARACTERISTICS_TERMINAL_SERVER_AWARE   = 0x8000  /**< Terminal Server aware. */
};


/* Data directory table offsets */
typedef enum
{
    PE_IMAGE_OPT_DD_OFF_EXPORT = 0,
    PE_IMAGE_OPT_DD_OFF_IMPORT,
    PE_IMAGE_OPT_DD_OFF_RESOURCE,
    PE_IMAGE_OPT_DD_OFF_EXCEPTION,
    PE_IMAGE_OPT_DD_OFF_CERTIFICATE,
    PE_IMAGE_OPT_DD_OFF_RELOCATION,
    PE_IMAGE_OPT_DD_OFF_DEBUG,
    PE_IMAGE_OPT_DD_OFF_ARCH,
    PE_IMAGE_OPT_DD_OFF_GLOBALPTR,
    PE_IMAGE_OPT_DD_OFF_TLS,
    PE_IMAGE_OPT_DD_OFF_LOADCONFIG,
    PE_IMAGE_OPT_DD_OFF_BOUNDIMPORT,
    PE_IMAGE_OPT_DD_OFF_IAT,
    PE_IMAGE_OPT_DD_OFF_DELAYIMPORT,
    PE_IMAGE_OPT_DD_OFF_CLRRUNTIME,
    PE_IMAGE_OPT_DD_OFF_RESERVED,
    PE_IMAGE_OPT_DD_MAXNUM
} pe64_datadir_off_t;


/* 5.6.2 Base Relocation Types */
enum
{
    PE_IMAGE_REL_BASED_ABSOLUTE       = 0,
    PE_IMAGE_REL_BASED_HIGH           = 1,
    PE_IMAGE_REL_BASED_LOW            = 2,
    PE_IMAGE_REL_BASED_HIGHLOW        = 3,
    PE_IMAGE_REL_BASED_HIGHADJ        = 4,
    PE_IMAGE_REL_BASED_MIPS_JMPADDR   = 5,
    PE_IMAGE_REL_BASED_ARM_MOV32A     = 5,
    PE_IMAGE_REL_BASED_ARM_MOV32T     = 7,
    PE_IMAGE_REL_BASED_MIPS_JMPADDR16 = 9,
    PE_IMAGE_REL_BASED_DIR64          = 10
};


#define PE_IMAGE_SCN_CNT_CODE               ((const uint32_t)0x00000020)
#define PE_IMAGE_SCN_CNT_INITIALIZED_DATA   ((const uint32_t)0x00000040)
#define PE_IMAGE_SCN_CNT_UNINITIALIZED_DATA ((const uint32_t)0x00000080)
#define PE_IMAGE_SCN_CNT_DATA               ((const uint32_t)(PE_IMAGE_SCN_CNT_INITIALIZED_DATA | PE_IMAGE_SCN_CNT_UNINITIALIZED_DATA))
#define PE_IMAGE_SCN_GPREL                  ((const uint32_t)0x00008000)
#define PE_IMAGE_SCN_LNK_NRELOC_OVFL        ((const uint32_t)0x01000000)
#define PE_IMAGE_SCN_MEM_DISCARDABLE        ((const uint32_t)0x02000000)
#define PE_IMAGE_SCN_MEM_NOT_CACHED         ((const uint32_t)0x04000000)
#define PE_IMAGE_SCN_MEM_NOT_PAGED          ((const uint32_t)0x08000000)
#define PE_IMAGE_SCN_MEM_SHARED             ((const uint32_t)0x10000000)
#define PE_IMAGE_SCN_MEM_EXECUTE            ((const uint32_t)0x20000000)
#define PE_IMAGE_SCN_MEM_READ               ((const uint32_t)0x40000000)
#define PE_IMAGE_SCN_MEM_WRITE              ((const uint32_t)0x80000000)


#endif /* X_WIN_BIN_PE_ENUM_H */
