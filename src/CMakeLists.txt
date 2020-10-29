include(xwinbin_asan)

set(libxwinbin_src_files
    pe_headers_parser.c
)

file(GLOB libxwinbin_public_header_files
    "${PROJECT_SOURCE_DIR}/include/xwinbin/*.h"
)

add_library(xwinbin STATIC ${libxwinbin_src_files})

# -std=c90
set_property(TARGET xwinbin PROPERTY C_EXTENSIONS OFF)
set_property(TARGET xwinbin PROPERTY C_STANDARD 90)

if(MSVC)
    target_compile_options(xwinbin PRIVATE
        /TC /W4 /WX /FA /Zl
    )
    target_link_options(xwinbin PRIVATE
        /NODEFAULTLIB
    )
else()
    target_compile_options(xwinbin PRIVATE
        -nostdlib -pedantic -Wall -Werror -Wextra -ffreestanding
    )
endif()


target_include_directories(xwinbin
    PUBLIC ${PROJECT_SOURCE_DIR}/include
    PRIVATE .
)

set_target_properties(xwinbin
    PROPERTIES
        PUBLIC_HEADER "${libxwinbin_public_header_files}"
)

INSTALL(TARGETS xwinbin
    LIBRARY DESTINATION lib
    ARCHIVE DESTINATION lib/static
    PUBLIC_HEADER DESTINATION include/xwinbin
)
