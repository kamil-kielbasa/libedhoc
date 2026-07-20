# SPDX-License-Identifier: MIT
#
# Build the portable, plain-C SP800-185 KMAC256 subset of XKCP as a Zephyr
# companion library for the libedhoc post-quantum cipher suite KDF
# (EDHOC_Extract / EDHOC_Expand, RFC 9528 Section 4.1). Only the plain-64bits
# Keccak-p[1600] permutation is compiled, so none of XKCP's code generation
# (make / xsltproc) runs during the Zephyr build.
#
# liboqs (ML-KEM / ML-DSA / SHAKE256) ships its own Zephyr module; only XKCP
# lacks upstream Zephyr support, so libedhoc builds it here. Included from
# zephyr/CMakeLists.txt when CONFIG_LIBEDHOC_CIPHER_SUITE_PQC_1_ENABLE=y.

# Locate the XKCP source tree: the west project (../modules/lib/XKCP) or the
# libedhoc externals/ submodule (plain git checkout). Override with -DXKCP_ROOT=.
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
        message(FATAL_ERROR
                "libedhoc PQC: XKCP sources not found (looked in "
                "../modules/lib/XKCP and externals/XKCP). Pass -DXKCP_ROOT=<path>.")
endif()

# High-level SP800-185 (KMAC256) + the KeccakWidth1600 sponge + the portable
# plain-64bits Keccak-p[1600] permutation.
zephyr_library_named(xkcp)
zephyr_library_sources(
        ${XKCP_ROOT}/lib/high/Keccak/SP800-185/SP800-185.c
        ${XKCP_ROOT}/lib/high/Keccak/KeccakSponge.c
        ${XKCP_ROOT}/lib/low/KeccakP-1600/plain-64bits/KeccakP-1600-opt64.c)

# Vendored third-party sources: do not fail the build on their warnings.
zephyr_library_compile_options(-w)

# Global include paths so the KMAC256 KDF source (edhoc_kdf_kmac256_xkcp.c),
# which the application compiles, also resolves "SP800-185.h" and the
# hand-written "config.h" in cmake/xkcp-zephyr/. The plain-64bits SnP directory
# is the only KeccakP-1600-SnP.h on the path, so there is no ambiguity.
zephyr_include_directories(
        ${CMAKE_CURRENT_LIST_DIR}/xkcp-zephyr
        ${XKCP_ROOT}/lib/common
        ${XKCP_ROOT}/lib/high/common
        ${XKCP_ROOT}/lib/high/Keccak
        ${XKCP_ROOT}/lib/high/Keccak/SP800-185
        ${XKCP_ROOT}/lib/low/common
        ${XKCP_ROOT}/lib/low/KeccakP-1600/common
        ${XKCP_ROOT}/lib/low/KeccakP-1600/plain-64bits
        ${XKCP_ROOT}/lib/low/KeccakP-1600/plain-64bits/SnP)
