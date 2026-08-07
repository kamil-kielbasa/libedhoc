# =============================================================================
# libedhoc_target_warnings(<target> <STRICT|TEST>)
#
# STRICT — production code. TEST — test and fuzz code, which relaxes the few
# warnings that Unity macros and CBOR test vectors legitimately trip.
# All flags are PRIVATE and never propagate to consumers.
#
# Clang's -Weverything is a development tool, tied to one clang version by the
# denials below, so it applies only when libedhoc is the top-level project.
# =============================================================================

include(CheckCCompilerFlag)

if(PROJECT_IS_TOP_LEVEL AND CMAKE_C_COMPILER_ID MATCHES "Clang")
    # Apple Clang's version does not track upstream Clang's version. Probe this
    # compatibility diagnostic so older Xcode toolchains keep working.
    check_c_compiler_flag("-Wpre-c11-compat"
        LIBEDHOC_COMPILER_HAS_WPRE_C11_COMPAT)
endif()

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
        set(extra_gcc   -Wswitch-enum -Wswitch-default -Wjump-misses-init)
        set(extra_clang "")
        # -Weverything must come first; everything after it is a deliberate
        # exception, each of which fights C itself rather than a defect.
        if(PROJECT_IS_TOP_LEVEL)
            set(extra_clang
                -Weverything
                -Wno-covered-switch-default       # every enum switch carries a
                                                  # default for out-of-range values
                -Wno-declaration-after-statement  # the project is C11
                -Wno-padded                       # informational; struct layout
                -Wno-unsafe-buffer-usage          # C has no bounds-safe alternative
                -Wno-vla)                         # the stack backend allocates VLAs
            if(APPLE)
                list(APPEND extra_clang
                    -Wno-poison-system-directories) # Apple Clang diagnoses its
                                                    # own /usr/local/include path
            endif()
            if(LIBEDHOC_COMPILER_HAS_WPRE_C11_COMPAT)
                list(APPEND extra_clang -Wno-pre-c11-compat)
            endif()
        endif()
    elseif(profile STREQUAL "TEST")
        # Unity declares tests via macros; test vectors store negative CBOR ints.
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
    endif()
endfunction()
