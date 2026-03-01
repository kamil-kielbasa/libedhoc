/**
 * \file    edhoc_log_backend.h
 * \author  Kamil Kielbasa
 * \brief   EDHOC logging implementation for Zephyr RTOS.
 * \version 1.0
 * \date    2026-01-27
 * 
 * \copyright Copyright (c) 2026
 */

/* Header guard ------------------------------------------------------------ */
#ifndef EDHOC_LOG_BACKEND_H
#define EDHOC_LOG_BACKEND_H

/* Include files ----------------------------------------------------------- */
#include <zephyr/logging/log.h>

/* Defines ----------------------------------------------------------------- */

/** Map EDHOC error log to Zephyr LOG_ERR. */
#define EDHOC_LOG_ERR(...) LOG_ERR(__VA_ARGS__)
/** Map EDHOC warning log to Zephyr LOG_WRN. */
#define EDHOC_LOG_WRN(...) LOG_WRN(__VA_ARGS__)
/** Map EDHOC info log to Zephyr LOG_INF. */
#define EDHOC_LOG_INF(...) LOG_INF(__VA_ARGS__)
/** Map EDHOC debug log to Zephyr LOG_DBG. */
#define EDHOC_LOG_DBG(...) LOG_DBG(__VA_ARGS__)

/** Map EDHOC info hex dump to Zephyr LOG_HEXDUMP_INF. */
#define EDHOC_LOG_HEXDUMP_INF(data, length, text) \
	LOG_HEXDUMP_INF(data, length, text)
/** Map EDHOC debug hex dump to Zephyr LOG_HEXDUMP_DBG. */
#define EDHOC_LOG_HEXDUMP_DBG(data, length, text) \
	LOG_HEXDUMP_DBG(data, length, text)

/* Types and type definitions ---------------------------------------------- */
/* Module interface variables and constants -------------------------------- */
/* Extern variables and constant declarations ------------------------------ */
/* Module interface function declarations ---------------------------------- */

#endif /* EDHOC_LOG_BACKEND_H */
