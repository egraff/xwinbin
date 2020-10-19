#ifndef X_WIN_BIN_ERR_H
#define X_WIN_BIN_ERR_H


typedef enum
{
    XWB_E_SUCCESS = 0,
    XWB_E_NEED_MORE_BYTES,
    XWB_E_INVALID_PE_FILE,
    XWB_E_INVALID_HEADERS,
    XWB_E_INVALID_SECTION_TABLE
} xwb_err_t;


#endif /* X_WIN_BIN_ERR_H */
