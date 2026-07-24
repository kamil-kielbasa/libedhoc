# =============================================================================
# edhoc_tests.cmake — helpers for the libedhoc Linux (Unity + CTest) test tree.
#
# Every category under tests/linux/ builds one or more small, standalone Unity
# binaries via edhoc_add_unity_test(). Each binary:
#
#   * compiles only the sources it needs (its reference cipher-suite source(s)),
#   * gets a generated main() that runs exactly its own TEST_GROUPs,
#   * registers itself so the orphan reconcile (edhoc_reconcile_linux_tree) can
#     fail the configure if a test .c is wired into no binary, and
#   * is wired into CTest with add_test().
# =============================================================================

set(EDHOC_TESTS_CMAKE_DIR ${CMAKE_CURRENT_LIST_DIR}
    CACHE INTERNAL "Directory holding the Unity runner template")

# Reference cipher-suite sources are compiled INTO the test binaries that use
# them. They lean on CBOR/format casts the strict TEST warning profile rejects,
# so relax exactly the flags the old monolith used for the same sources.
set(EDHOC_SUITE_SRC_WARN_FLAGS
    "-Wno-format -Wno-format-pedantic -Wno-sign-conversion -Wno-conversion -Wno-switch-enum"
    CACHE INTERNAL "Relaxed warnings for compiled reference cipher-suite sources")

define_property(GLOBAL PROPERTY EDHOC_TEST_REGISTRY
    BRIEF_DOCS "Every libedhoc Unity test binary registered in this tree"
    FULL_DOCS  "Populated by edhoc_add_unity_test(); asserted non-empty by \
edhoc_assert_registry_nonempty().")

define_property(GLOBAL PROPERTY EDHOC_TEST_CONSUMED_SOURCES
    BRIEF_DOCS "Absolute paths of every test .c consumed by a binary"
    FULL_DOCS  "Populated by edhoc_add_unity_test(); reconciled against on-disk \
test_*.c by edhoc_reconcile_linux_tree() to catch orphans.")


# -----------------------------------------------------------------------------
# edhoc_add_unity_test(
#     NAME           <binary name>
#     SOURCES        <test .c files owning the TEST_GROUPs>
#     GROUPS         <Unity fixture TEST_GROUP names>
#     [SUITE_SOURCES <reference suite .c, compiled with relaxed warnings>]
#     [INCLUDE       <extra include dirs>]
#     [LINK          <extra link libraries>]
#     [DEFINES       <extra compile definitions>]
#     [PQC]          <wire liboqs + XKCP for the post-quantum suite pqc_1>)
# -----------------------------------------------------------------------------
function(edhoc_add_unity_test)
    cmake_parse_arguments(T "PQC" "NAME"
        "SOURCES;GROUPS;SUITE_SOURCES;INCLUDE;LINK;DEFINES" ${ARGN})

    if(NOT T_NAME)
        message(FATAL_ERROR "edhoc_add_unity_test: NAME is required")
    endif()
    if(NOT T_GROUPS)
        message(FATAL_ERROR "edhoc_add_unity_test(${T_NAME}): GROUPS is required")
    endif()

    # --- Generate the runner main() from the group list ----------------------
    set(_run "")
    foreach(_g ${T_GROUPS})
        string(APPEND _run "\tRUN_TEST_GROUP(${_g});\n")
    endforeach()
    set(EDHOC_RUN_TEST_GROUPS "${_run}")

    set(_main ${CMAKE_CURRENT_BINARY_DIR}/${T_NAME}_main.c)
    configure_file(${EDHOC_TESTS_CMAKE_DIR}/unity_runner.c.in ${_main} @ONLY)

    # --- Executable ----------------------------------------------------------
    add_executable(${T_NAME} ${_main} ${T_SOURCES} ${T_SUITE_SOURCES})

    if(T_SUITE_SOURCES)
        set_source_files_properties(${T_SUITE_SOURCES} PROPERTIES
            COMPILE_FLAGS "${EDHOC_SUITE_SRC_WARN_FLAGS}")
    endif()

    # --- Includes / libraries ------------------------------------------------
    target_include_directories(${T_NAME} PRIVATE
        ${LIBEDHOC_INTERNAL_INCLUDE_DIR}
        ${T_INCLUDE})

    target_link_libraries(${T_NAME} PRIVATE
        libedhoc::edhoc
        libedhoc::cipher_suites
        libedhoc::backend_memory
        unity
        ${T_LINK})

    # --- Compile definitions -------------------------------------------------
    if(T_DEFINES)
        target_compile_definitions(${T_NAME} PRIVATE ${T_DEFINES})
    endif()
    if(LIBEDHOC_ENABLE_TESTS_TRACES)
        target_compile_definitions(${T_NAME} PRIVATE TEST_TRACES)
    endif()

    # --- Post-quantum suite (liboqs + XKCP) ----------------------------------
    # These targets only exist when the pqc suite is enabled, which is exactly
    # when a PQC binary is added. XKCP's generated SP800-185.h comes from
    # xkcp_build, so make the target wait for it.
    if(T_PQC)
        target_link_libraries(${T_NAME} PRIVATE oqs xkcp)
        target_include_directories(${T_NAME} PRIVATE
            ${CMAKE_BINARY_DIR}/externals/liboqs/include
            ${LIBEDHOC_ROOT_DIR}/externals/liboqs/src
            ${XKCP_INCLUDE_DIR})
        add_dependencies(${T_NAME} xkcp_build)
    endif()

    # --- Warnings + instrumentation ------------------------------------------
    libedhoc_target_warnings(${T_NAME} TEST)

    if(LIBEDHOC_ENABLE_COVERAGE)
        target_compile_options(${T_NAME} PRIVATE --coverage)
        target_link_options(${T_NAME} PRIVATE --coverage)
    endif()
    if(LIBEDHOC_ENABLE_SANITIZERS)
        target_compile_options(${T_NAME} PRIVATE
            -fsanitize=address,undefined -fno-omit-frame-pointer)
        target_link_options(${T_NAME} PRIVATE -fsanitize=address,undefined)
    endif()

    # --- Register with CTest + the orphan reconcile --------------------------
    add_test(NAME ${T_NAME} COMMAND ${T_NAME})

    set_property(GLOBAL APPEND PROPERTY EDHOC_TEST_REGISTRY ${T_NAME})

    foreach(_s ${T_SOURCES})
        get_filename_component(_abs ${_s} ABSOLUTE)
        set_property(GLOBAL APPEND PROPERTY EDHOC_TEST_CONSUMED_SOURCES ${_abs})
    endforeach()
endfunction()


# -----------------------------------------------------------------------------
# edhoc_assert_registry_nonempty()
#
# A tests-enabled preset that registered no binaries means no cipher suite was
# enabled — fail the configure loudly rather than pass vacuously.
# -----------------------------------------------------------------------------
function(edhoc_assert_registry_nonempty)
    get_property(_reg GLOBAL PROPERTY EDHOC_TEST_REGISTRY)

    if(NOT _reg)
        message(FATAL_ERROR
            "No test binaries were registered for this configuration. A preset "
            "that builds tests/linux must enable at least one cipher suite.")
    endif()
endfunction()


# -----------------------------------------------------------------------------
# edhoc_reconcile_linux_tree(<root>)
#
# Anti-silent-skip net #1 (configure time): in an ALL-SUITES build every
# test_*.c under <root> (excluding support/ helpers) must have been consumed by
# some edhoc_add_unity_test(). A file present on disk but wired into no binary
# would otherwise silently never run.
#
# Runs only when all suites are enabled — under a single-suite preset most test
# files are legitimately skipped (their suite is off). The CI check-matrix job
# (net #2) covers the per-preset union across the whole matrix. Backend-only
# tests (mem_custom needs the custom backend) are excluded: the default build
# uses the stack backend.
# -----------------------------------------------------------------------------
function(edhoc_reconcile_linux_tree root)
    if(NOT (CONFIG_LIBEDHOC_CIPHER_SUITE_0_ENABLE AND
            CONFIG_LIBEDHOC_CIPHER_SUITE_2_ENABLE AND
            CONFIG_LIBEDHOC_CIPHER_SUITE_4_ENABLE AND
            CONFIG_LIBEDHOC_CIPHER_SUITE_24_ENABLE AND
            CONFIG_LIBEDHOC_CIPHER_SUITE_PQC_1_ENABLE))
        return()
    endif()

    file(GLOB_RECURSE _files ${root}/test_*.c)
    list(FILTER _files EXCLUDE REGEX "/support/")
    list(FILTER _files EXCLUDE REGEX "test_handshake_mem_custom\\.c$")

    get_property(_consumed GLOBAL PROPERTY EDHOC_TEST_CONSUMED_SOURCES)

    set(_orphans "")
    foreach(_f ${_files})
        if(NOT _f IN_LIST _consumed)
            list(APPEND _orphans ${_f})
        endif()
    endforeach()

    if(_orphans)
        string(REPLACE ";" "\n  " _pretty "${_orphans}")
        message(FATAL_ERROR
            "Orphaned test source(s) present on disk but wired into no test "
            "binary (they would silently never run):\n  ${_pretty}")
    endif()
endfunction()
