/**
 * \file    edhoc_log.h
 * \author  Kamil Kielbasa
 * \brief   EDHOC logging module.
 * \version 1.0
 * \date    2026-01-27
 * 
 * \copyright Copyright (c) 2026
 */

/* Header guard ------------------------------------------------------------ */
#ifndef EDHOC_LOG_H
#define EDHOC_LOG_H

/* Include files ----------------------------------------------------------- */
#include "edhoc_log_backend.h"

/* Defines ----------------------------------------------------------------- */

/** \defgroup edhoc-log EDHOC logging
 *
 * Compile-time log level selection. The backend (Linux or Zephyr) is
 * included via edhoc_log_backend.h and provides the actual macro
 * implementations.  When the configured level is below a given severity
 * the corresponding macro expands to a no-op.
 *
 * @{
 */

/** Log level: logging disabled. */
#define EDHOC_LOG_LEVEL_NONE 0
/** Log level: errors only. */
#define EDHOC_LOG_LEVEL_ERR 1
/** Log level: errors and warnings. */
#define EDHOC_LOG_LEVEL_WRN 2
/** Log level: errors, warnings and informational messages. */
#define EDHOC_LOG_LEVEL_INF 3
/** Log level: all messages including debug. */
#define EDHOC_LOG_LEVEL_DBG 4

#ifndef CONFIG_LIBEDHOC_LOG_LEVEL
/** Default log level when not specified by the build system. */
#define CONFIG_LIBEDHOC_LOG_LEVEL EDHOC_LOG_LEVEL_NONE
#endif

/**
 * \def EDHOC_LOG_ERR(...)
 * \brief Log an error message (printf-style).
 *
 * Active when CONFIG_LIBEDHOC_LOG_LEVEL >= EDHOC_LOG_LEVEL_ERR.
 */
#if CONFIG_LIBEDHOC_LOG_LEVEL >= EDHOC_LOG_LEVEL_ERR
#ifndef EDHOC_LOG_ERR
#define EDHOC_LOG_ERR(...)
#endif
#else
#ifdef EDHOC_LOG_ERR
#undef EDHOC_LOG_ERR
#endif
#define EDHOC_LOG_ERR(...) \
	do {               \
	} while (0)
#endif

/**
 * \def EDHOC_LOG_WRN(...)
 * \brief Log a warning message (printf-style).
 *
 * Active when CONFIG_LIBEDHOC_LOG_LEVEL >= EDHOC_LOG_LEVEL_WRN.
 */
#if CONFIG_LIBEDHOC_LOG_LEVEL >= EDHOC_LOG_LEVEL_WRN
#ifndef EDHOC_LOG_WRN
#define EDHOC_LOG_WRN(...)
#endif
#else
#ifdef EDHOC_LOG_WRN
#undef EDHOC_LOG_WRN
#endif
#define EDHOC_LOG_WRN(...) \
	do {               \
	} while (0)
#endif

/**
 * \def EDHOC_LOG_INF(...)
 * \brief Log an informational message (printf-style).
 *
 * Active when CONFIG_LIBEDHOC_LOG_LEVEL >= EDHOC_LOG_LEVEL_INF.
 *
 * \def EDHOC_LOG_HEXDUMP_INF(data, length, text)
 * \brief Hex-dump \p data with an informational header.
 *
 * \param data     Pointer to the buffer to dump.
 * \param length   Number of bytes.
 * \param text     Descriptive text printed before the hex dump.
 */
#if CONFIG_LIBEDHOC_LOG_LEVEL >= EDHOC_LOG_LEVEL_INF
#ifndef EDHOC_LOG_INF
#define EDHOC_LOG_INF(...)
#endif
#ifndef EDHOC_LOG_HEXDUMP_INF
#define EDHOC_LOG_HEXDUMP_INF(data, length, text)
#endif
#else
#ifdef EDHOC_LOG_INF
#undef EDHOC_LOG_INF
#endif
#ifdef EDHOC_LOG_HEXDUMP_INF
#undef EDHOC_LOG_HEXDUMP_INF
#endif
#define EDHOC_LOG_INF(...) \
	do {               \
	} while (0)
#define EDHOC_LOG_HEXDUMP_INF(data, length, text) \
	do {                                      \
	} while (0)
#endif

/**
 * \def EDHOC_LOG_DBG(...)
 * \brief Log a debug message (printf-style).
 *
 * Active when CONFIG_LIBEDHOC_LOG_LEVEL >= EDHOC_LOG_LEVEL_DBG.
 * Debug messages include the calling function name.
 *
 * \def EDHOC_LOG_HEXDUMP_DBG(data, length, text)
 * \brief Hex-dump \p data with a debug header.
 *
 * \param data     Pointer to the buffer to dump.
 * \param length   Number of bytes.
 * \param text     Descriptive text printed before the hex dump.
 */
#if CONFIG_LIBEDHOC_LOG_LEVEL >= EDHOC_LOG_LEVEL_DBG
#ifndef EDHOC_LOG_DBG
#define EDHOC_LOG_DBG(...)
#endif
#ifndef EDHOC_LOG_HEXDUMP_DBG
#define EDHOC_LOG_HEXDUMP_DBG(data, length, text)
#endif
#else
#ifdef EDHOC_LOG_DBG
#undef EDHOC_LOG_DBG
#endif
#ifdef EDHOC_LOG_HEXDUMP_DBG
#undef EDHOC_LOG_HEXDUMP_DBG
#endif
#define EDHOC_LOG_DBG(...) \
	do {               \
	} while (0)
#define EDHOC_LOG_HEXDUMP_DBG(data, length, text) \
	do {                                      \
	} while (0)
#endif

/**@}*/

/* Types and type definitions ---------------------------------------------- */
/* Module interface variables and constants -------------------------------- */
/* Extern variables and constant declarations ------------------------------ */
/* Module interface function declarations ---------------------------------- */

#endif /* EDHOC_LOG_H */
