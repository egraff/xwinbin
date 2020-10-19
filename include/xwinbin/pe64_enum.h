#ifndef X_WIN_BIN_PE64_ENUM_H
#define X_WIN_BIN_PE64_ENUM_H


/* 5.1.2 Debug Type */
typedef enum {
    PE_IMAGE_DEBUG_TYPE_UNKNOWN       = 0,
    PE_IMAGE_DEBUG_TYPE_COFF          = 1,
    PE_IMAGE_DEBUG_TYPE_CODEVIEW      = 2,
    PE_IMAGE_DEBUG_TYPE_FPO           = 3,
    PE_IMAGE_DEBUG_TYPE_MISC          = 4,
    PE_IMAGE_DEBUG_TYPE_EXCEPTION     = 5,
    PE_IMAGE_DEBUG_TYPE_FIXUP         = 6,
    PE_IMAGE_DEBUG_TYPE_OMAP_TO_SRC   = 7,
    PE_IMAGE_DEBUG_TYPE_OMAP_FROM_SRC = 8,
    PE_IMAGE_DEBUG_TYPE_BORLAND       = 9,
    PE_IMAGE_DEBUG_TYPE_RESERVED10    = 10,
    PE_IMAGE_DEBUG_TYPE_CLSID         = 11,
} pe64_debug_type_t;


typedef enum {
    PE_UNW_FLAG_NHANDLER  = 0,
    PE_UNW_FLAG_EHANDLER  = (1 << 0),
    PE_UNW_FLAG_UHANDLER  = (1 << 1),
    PE_UNW_FLAG_CHAININFO = (1 << 2), /* Cannot be combined with PE_UNW_FLAG_EHANDLER or PE_UNW_FLAG_UHANDLER */
} pe64_unwind_flag_t;


typedef enum {
    PE_UWOP_PUSH_NONVOL     = 0,
    PE_UWOP_ALLOC_LARGE     = 1,
    PE_UWOP_ALLOC_SMALL     = 2,
    PE_UWOP_SET_FPREG       = 3,
    PE_UWOP_SAVE_NONVOL     = 4,
    PE_UWOP_SAVE_NONVOL_FAR = 5,
    PE_UWOP_6               = 6, /* ??? */
    PE_UWOP_SAVE_XMM128     = 8,
    PE_UWOP_SAVE_XMM128_FAR = 9,
    PE_UWOP_PUSH_MACHFRAME  = 10,
} pe64_unwind_op_t;


typedef enum {
    PE_UNW_REG_RAX = 0,
    PE_UNW_REG_RCX = 1,
    PE_UNW_REG_RDX = 2,
    PE_UNW_REG_RBX = 3,
    PE_UNW_REG_RSP = 4,
    PE_UNW_REG_RBP = 5,
    PE_UNW_REG_RSI = 6,
    PE_UNW_REG_RDI = 7,
    PE_UNW_REG_R8  = 8,
    PE_UNW_REG_R9  = 9,
    PE_UNW_REG_R10 = 10,
    PE_UNW_REG_R11 = 11,
    PE_UNW_REG_R12 = 12,
    PE_UNW_REG_R13 = 13,
    PE_UNW_REG_R14 = 14,
    PE_UNW_REG_R15 = 15,
} pe64_unwind_reg_t;


typedef enum {
    PE_UNW_MACHFRAME_WITHOUT_ERRCODE = 0,
    PE_UNW_MACHFRAME_WITH_ERRCODE    = 1,
} pe64_unwind_machframe_type_t;


#endif /* X_WIN_BIN_PE64_ENUM_H */
