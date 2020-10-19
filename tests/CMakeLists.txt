include(xwinbin_asan)

# https://cmake.org/cmake/help/latest/command/add_library.html#interface-libraries
add_library(xwinbin_tests INTERFACE)

if(MSVC)
    target_compile_options(xwinbin_tests INTERFACE
        /TC /W4 /WX /FA
    )
else()
    target_compile_options(xwinbin_tests INTERFACE
        -Wall -Werror -Wextra
    )
endif()

target_include_directories(xwinbin_tests
    INTERFACE ${PROJECT_SOURCE_DIR}/include
    INTERFACE .
)

target_link_libraries(xwinbin_tests INTERFACE xwinbin)


### Tests ###

add_executable(test_pe_headers_parser test_pe_headers_parser.c)
target_link_libraries(test_pe_headers_parser PRIVATE xwinbin_tests)
add_test(NAME test_pe_headers_parser COMMAND test_pe_headers_parser)
