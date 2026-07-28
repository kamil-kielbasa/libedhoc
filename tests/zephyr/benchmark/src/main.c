/**
 * \file    main.c
 * \author  Kamil Kielbasa
 * \brief   EDHOC handshake benchmark — ztest suite registration.
 *
 *          The benchmark harness (handshake spine, timing, reporting and the
 *          per-case runner) lives under driver/; each cipher suite is a ztest
 *          case in its own benchmark_suite_*.c. This file only registers the
 *          ztest suite that groups them.
 *
 * \copyright Copyright (c) 2026
 *
 */

/* Include files ----------------------------------------------------------- */

/* Zephyr headers: */
#include <zephyr/ztest.h>

/* Module interface function definitions ----------------------------------- */

ZTEST_SUITE(edhoc_benchmark, NULL, NULL, NULL, NULL, NULL);
