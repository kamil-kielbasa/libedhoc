/*
 * Minimal XKCP configuration for the libedhoc Zephyr build.
 *
 * The upstream XKCP config.h is produced by XKCP's own make + xsltproc code
 * generator, which selects platform-specific implementations. The Zephyr build
 * does not run that generator; it compiles only the portable plain-64bits
 * Keccak-p[1600] permutation, so the single feature flag below is all the
 * SP800-185 / KeccakSponge / permutation headers need.
 *
 * XKCP's public headers include "config.h" (unqualified), so this directory is
 * placed on a Zephyr global include path. The file defines only the XKCP
 * permutation feature macro to minimise the chance of clashing with an
 * unrelated component that also includes a bare "config.h".
 */
#ifndef XKCP_has_KeccakP1600
#define XKCP_has_KeccakP1600
#endif
