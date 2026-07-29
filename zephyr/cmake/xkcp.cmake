# =============================================================================
# XKCP — SP800-185 KMAC256, as a Zephyr companion library.
#
# Only the portable plain-64bits Keccak-p[1600] permutation is compiled, so
# XKCP's own code generation never runs during a Zephyr build. XKCP has no
# upstream Zephyr module, so libedhoc builds it here.
# =============================================================================

# Source tree: the west project, or the libedhoc submodule. Override with
# -DXKCP_ROOT=<path>.
if(NOT DEFINED XKCP_ROOT)
    foreach(_xkcp_cand
            ${ZEPHYR_CURRENT_MODULE_DIR}/../modules/lib/XKCP
            ${ZEPHYR_CURRENT_MODULE_DIR}/externals/XKCP)
        if(EXISTS ${_xkcp_cand}/lib/high/Keccak/SP800-185/SP800-185.c)
            set(XKCP_ROOT ${_xkcp_cand})
            break()
        endif()
    endforeach()
endif()

if(NOT XKCP_ROOT OR NOT EXISTS ${XKCP_ROOT}/lib/high/Keccak/SP800-185/SP800-185.c)
    message(FATAL_ERROR "XKCP sources not found; pass -DXKCP_ROOT=<path>.")
endif()

zephyr_library_named(xkcp)
zephyr_library_sources(
    ${XKCP_ROOT}/lib/high/Keccak/SP800-185/SP800-185.c
    ${XKCP_ROOT}/lib/high/Keccak/KeccakSponge.c
    ${XKCP_ROOT}/lib/low/KeccakP-1600/plain-64bits/KeccakP-1600-opt64.c)

# Vendored third-party sources: do not fail the build on their warnings.
zephyr_library_compile_options(-w)

# Global, so the KDF source compiled by the application resolves these headers
# and the hand-written config.h next to this file.
zephyr_include_directories(
    ${CMAKE_CURRENT_LIST_DIR}/xkcp
    ${XKCP_ROOT}/lib/common
    ${XKCP_ROOT}/lib/high/common
    ${XKCP_ROOT}/lib/high/Keccak
    ${XKCP_ROOT}/lib/high/Keccak/SP800-185
    ${XKCP_ROOT}/lib/low/common
    ${XKCP_ROOT}/lib/low/KeccakP-1600/common
    ${XKCP_ROOT}/lib/low/KeccakP-1600/plain-64bits
    ${XKCP_ROOT}/lib/low/KeccakP-1600/plain-64bits/SnP)
