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

#define EDHOC_LOG_LEVEL_NONE 0
#define EDHOC_LOG_LEVEL_ERR 1
#define EDHOC_LOG_LEVEL_WRN 2
#define EDHOC_LOG_LEVEL_INF 3
#define EDHOC_LOG_LEVEL_DBG 4

#ifndef CONFIG_LIBEDHOC_LOG_LEVEL
#define CONFIG_LIBEDHOC_LOG_LEVEL EDHOC_LOG_LEVEL_NONE
#endif

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

/* Types and type definitions ---------------------------------------------- */
/* Module interface variables and constants -------------------------------- */
/* Extern variables and constant declarations ------------------------------ */
/* Module interface function declarations ---------------------------------- */

#endif /* EDHOC_LOG_H */
