# =============================================================================
# compact25519 — Ed25519 signatures, as a Zephyr companion library.
#
# compact25519 has no upstream Zephyr module, so libedhoc builds it here.
# Included from zephyr/CMakeLists.txt by the cipher suites that need it.
# =============================================================================

# Source tree: the west project, or the libedhoc submodule. Override with
# -DCOMPACT25519_ROOT=<path>.
if(NOT DEFINED COMPACT25519_ROOT)
    foreach(_c25519_cand
            ${ZEPHYR_CURRENT_MODULE_DIR}/../modules/lib/compact25519
            ${ZEPHYR_CURRENT_MODULE_DIR}/externals/compact25519)
        if(EXISTS ${_c25519_cand}/src/compact_ed25519.c)
            set(COMPACT25519_ROOT ${_c25519_cand})
            break()
        endif()
    endforeach()
endif()

if(NOT COMPACT25519_ROOT OR NOT EXISTS ${COMPACT25519_ROOT}/src/compact_ed25519.c)
    message(FATAL_ERROR
            "compact25519 sources not found; pass -DCOMPACT25519_ROOT=<path>.")
endif()

zephyr_library_named(compact25519)
zephyr_library_sources(
    ${COMPACT25519_ROOT}/src/compact_ed25519.c
    ${COMPACT25519_ROOT}/src/compact_wipe.c
    ${COMPACT25519_ROOT}/src/compact_x25519.c
    ${COMPACT25519_ROOT}/src/c25519/c25519.c
    ${COMPACT25519_ROOT}/src/c25519/ed25519.c
    ${COMPACT25519_ROOT}/src/c25519/edsign.c
    ${COMPACT25519_ROOT}/src/c25519/f25519.c
    ${COMPACT25519_ROOT}/src/c25519/fprime.c
    ${COMPACT25519_ROOT}/src/c25519/sha512.c)

# Vendored third-party sources: do not fail the build on their warnings.
zephyr_library_compile_options(-w)

# Global, so the reference cipher-suite sources compiled by the application
# resolve these headers too.
zephyr_include_directories(
    ${COMPACT25519_ROOT}/src
    ${COMPACT25519_ROOT}/src/c25519)
