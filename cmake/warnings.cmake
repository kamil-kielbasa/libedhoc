# =============================================================================
# libedhoc_target_warnings(<target> <STRICT|TEST>)
#
# Single source of truth for the project's warning flags.
#
# Two profiles, sharing one common base:
#   STRICT — production code (the core library). Maximal strictness.
#   TEST   — test / fuzz code. Same base, but a few warnings are turned into
#            -Wno-* because Unity macros and CBOR test vectors legitimately
#            trip them (nested externs, missing declarations, sign conversion).
#
# All flags are added PRIVATE: warnings are a build concern of THIS target and
# must never propagate to consumers.
# =============================================================================

function(libedhoc_target_warnings target profile)
    # --- Common base (identical for both profiles) ---------------------------
    set(base
        -Werror -Wall -Wextra -pedantic
        -Wconversion -Wcast-align -Wdouble-promotion
        -Wformat=2 -Wunreachable-code
        -Wmissing-prototypes -Wstrict-prototypes -Wold-style-definition
        -Wshadow -Wundef -Wwrite-strings -Wpointer-arith -Wuninitialized
        -Wmissing-include-dirs -Wnull-dereference)

    set(base_gcc
        -Wformat-overflow=2 -Wformat-truncation=2
        -Wduplicated-cond -Wduplicated-branches -Wlogical-op -Winit-self)

    # --- Profile-specific additions ------------------------------------------
    if(profile STREQUAL "STRICT")
        list(APPEND base -Wsign-conversion -Wmissing-declarations -Wnested-externs)
        set(extra_gcc   -Wswitch-enum -Wjump-misses-init)
        set(extra_clang -Wno-vla -Wno-declaration-after-statement
                        -Wno-covered-switch-default -Wno-padded -Wno-switch-default)
    elseif(profile STREQUAL "TEST")
        # Suppressed for test code:
        #  - missing-declarations / nested-externs: Unity declares test
        #    functions via macros and uses nested extern declarations.
        #  - sign-conversion: test vectors store negative CBOR ints in uint8_t.
        list(APPEND base -Wno-missing-declarations -Wno-sign-conversion)
        set(extra_gcc   -Wno-nested-externs)
        set(extra_clang "")
    else()
        message(FATAL_ERROR
            "libedhoc_target_warnings: unknown profile '${profile}' (use STRICT or TEST)")
    endif()

    # --- Compiler family (detected once, here) -------------------------------
    if(CMAKE_C_COMPILER_ID STREQUAL "GNU")
        target_compile_options(${target} PRIVATE ${base} ${base_gcc} ${extra_gcc})
    elseif(CMAKE_C_COMPILER_ID MATCHES "Clang")
        target_compile_options(${target} PRIVATE ${base} ${extra_clang})
        # -Wunsafe-buffer-usage is a newer Clang warning that is far too noisy
        # for this code base; silence it only on STRICT and only where supported.
        if(profile STREQUAL "STRICT")
            include(CheckCCompilerFlag)
            check_c_compiler_flag(-Wunsafe-buffer-usage HAS_WUNSAFE_BUFFER_USAGE)
            if(HAS_WUNSAFE_BUFFER_USAGE)
                target_compile_options(${target} PRIVATE -Wno-unsafe-buffer-usage)
            endif()
        endif()
    endif()
endfunction()
