/**
 * \file    user-mbedtls.h
 * \author  libedhoc
 * \brief   Extra mbedTLS defines for the cipher-suite-2 benchmark helpers.
 *
 *          Included via MBEDTLS_USER_CONFIG_FILE after Zephyr's
 *          config-mbedtls.h.  Force-enables the PK and OID modules that the
 *          cipher-suite-2 helpers need, without pulling in the full X.509 /
 *          PK_WRITE Kconfig chain.
 *
 * \version 1.0
 * \date    2026-02-27
 *
 * \copyright Copyright (c) 2026
 *
 */

#ifndef USER_MBEDTLS_H
#define USER_MBEDTLS_H

#ifndef MBEDTLS_PK_C
#define MBEDTLS_PK_C
#endif

#ifndef MBEDTLS_OID_C
#define MBEDTLS_OID_C
#endif

#endif /* USER_MBEDTLS_H */
