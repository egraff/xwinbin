# https://stackoverflow.com/a/10055571/2646573
if (CMAKE_C_COMPILER_ID MATCHES "Clang")
    if (CMAKE_C_COMPILER_FRONTEND_VARIANT STREQUAL "MSVC")
        # using clang with clang-cl front end
        set(CMAKE_C_FLAGS_ASAN
            "-fsanitize=address /Zi /MDd"
            CACHE STRING "CFLAGS for Asan build type" FORCE
        )

        set(CMAKE_EXE_LINKER_FLAGS_ASAN
            "/debug -incremental:no /wholearchive:clang_rt.asan_dynamic-x86_64.lib /wholearchive:clang_rt.asan_dynamic_runtime_thunk-x86_64.lib"
        )

        set(CMAKE_SHARED_LINKER_FLAGS_ASAN
            "/debug -incremental:no /wholearchive:clang_rt.asan_dynamic-x86_64.lib /wholearchive:clang_rt.asan_dynamic_runtime_thunk-x86_64.lib"
        )
    elseif (CMAKE_C_COMPILER_FRONTEND_VARIANT STREQUAL "GNU")
        set(CMAKE_C_FLAGS_ASAN
            "-fsanitize=address -fno-omit-frame-pointer"
            CACHE STRING "CFLAGS for Asan build type" FORCE
        )

        set(CMAKE_EXE_LINKER_FLAGS_ASAN
            "-fsanitize=address"
        )

        set(CMAKE_SHARED_LINKER_FLAGS_ASAN
            "-fsanitize=address"
        )
    endif()
elseif (CMAKE_C_COMPILER_ID STREQUAL "GNU")
    set(CMAKE_C_FLAGS_ASAN
        "-fsanitize=address -fno-omit-frame-pointer"
        CACHE STRING "CFLAGS for Asan build type" FORCE
    )

    set(CMAKE_EXE_LINKER_FLAGS_ASAN
        "-fsanitize=address"
    )

    set(CMAKE_SHARED_LINKER_FLAGS_ASAN
        "-fsanitize=address"
    )
elseif (CMAKE_C_COMPILER_ID STREQUAL "MSVC")
    set(CMAKE_C_FLAGS_ASAN
        "-fsanitize=address /Zi /MDd"
        CACHE STRING "CFLAGS for Asan build type" FORCE
    )

    set(CMAKE_EXE_LINKER_FLAGS_ASAN
        "/debug -incremental:no /wholearchive:clang_rt.asan_dynamic-x86_64.lib /wholearchive:clang_rt.asan_dynamic_runtime_thunk-x86_64.lib"
    )

    set(CMAKE_SHARED_LINKER_FLAGS_ASAN
        "/debug -incremental:no /wholearchive:clang_rt.asan_dynamic-x86_64.lib /wholearchive:clang_rt.asan_dynamic_runtime_thunk-x86_64.lib"
    )
endif()
