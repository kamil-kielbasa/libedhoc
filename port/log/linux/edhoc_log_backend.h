/**
 * \file    edhoc_log_backend.h
 * \author  Kamil Kielbasa
 * \brief   EDHOC logging backend for Linux.
 * \version 1.0
 * \date    2026-01-27
 * 
 * \copyright Copyright (c) 2026
 */

/* Header guard ------------------------------------------------------------ */
#ifndef EDHOC_LOG_BACKEND_H
#define EDHOC_LOG_BACKEND_H

/* Include files ----------------------------------------------------------- */
#include <stdio.h>
#include <stdint.h>
#include <string.h>
#include <time.h>
#include <sys/time.h>

/* Defines ----------------------------------------------------------------- */

/** ANSI escape: red (used for error level). */
#define ANSI_COLOR_RED "\x1b[31m"
/** ANSI escape: yellow (used for warning level). */
#define ANSI_COLOR_YELLOW "\x1b[33m"
/** ANSI escape: green (used for info level). */
#define ANSI_COLOR_GREEN "\x1b[32m"
/** ANSI escape: cyan (used for debug level). */
#define ANSI_COLOR_CYAN "\x1b[36m"
/** ANSI escape: reset terminal color. */
#define ANSI_COLOR_RESET "\x1b[0m"

/**
 * \brief Format current wall-clock time into a timestamp string.
 *
 * Writes "[HH:MM:SS.mmm,uuu]" into \p buffer using gettimeofday().
 *
 * \param[out] buffer   Destination buffer (at least 22 bytes).
 * \param      size     Size of \p buffer in bytes.
 */
static inline void edhoc_log_get_timestamp(char *buffer, size_t size)
{
	struct timeval tv;
	struct tm *tm_info;

	gettimeofday(&tv, NULL);
	tm_info = localtime(&tv.tv_sec);

	const int milliseconds = (int)(tv.tv_usec / 1000);
	const int microseconds = (int)(tv.tv_usec % 1000);

	(void)snprintf(buffer, size, "[%02d:%02d:%02d.%03d,%03d]",
		       tm_info->tm_hour % 24, tm_info->tm_min % 60,
		       tm_info->tm_sec % 60, milliseconds % 1000,
		       microseconds % 1000);
}

#define EDHOC_LOG_ERR(...)                                                  \
	do {                                                                \
		char timestamp[32];                                         \
		edhoc_log_get_timestamp(timestamp, sizeof(timestamp));      \
		(void)fflush(stdout);                                       \
		(void)fprintf(stderr,                                       \
			      "%s " ANSI_COLOR_RED "<err>" ANSI_COLOR_RESET \
			      " libedhoc: ",                                \
			      timestamp);                                   \
		(void)fprintf(stderr, __VA_ARGS__);                         \
		(void)fprintf(stderr, "\n");                                \
		(void)fflush(stderr);                                       \
	} while (0)

#define EDHOC_LOG_WRN(...)                                                     \
	do {                                                                   \
		char timestamp[32];                                            \
		edhoc_log_get_timestamp(timestamp, sizeof(timestamp));         \
		(void)fflush(stdout);                                          \
		(void)fprintf(stdout,                                          \
			      "%s " ANSI_COLOR_YELLOW "<wrn>" ANSI_COLOR_RESET \
			      " libedhoc: ",                                   \
			      timestamp);                                      \
		(void)fprintf(stdout, __VA_ARGS__);                            \
		(void)fprintf(stdout, "\n");                                   \
		(void)fflush(stdout);                                          \
	} while (0)

#define EDHOC_LOG_INF(...)                                                    \
	do {                                                                  \
		char timestamp[32];                                           \
		edhoc_log_get_timestamp(timestamp, sizeof(timestamp));        \
		(void)fflush(stdout);                                         \
		(void)fprintf(stdout,                                         \
			      "%s " ANSI_COLOR_GREEN "<inf>" ANSI_COLOR_RESET \
			      " libedhoc: ",                                  \
			      timestamp);                                     \
		(void)fprintf(stdout, __VA_ARGS__);                           \
		(void)fprintf(stdout, "\n");                                  \
		(void)fflush(stdout);                                         \
	} while (0)

#define EDHOC_LOG_DBG(...)                                                   \
	do {                                                                 \
		char timestamp[32];                                          \
		edhoc_log_get_timestamp(timestamp, sizeof(timestamp));       \
		(void)fflush(stdout);                                        \
		(void)fprintf(stdout,                                        \
			      "%s " ANSI_COLOR_CYAN "<dbg>" ANSI_COLOR_RESET \
			      " libedhoc: %s: ",                             \
			      timestamp, __func__);                          \
		(void)fprintf(stdout, __VA_ARGS__);                          \
		(void)fprintf(stdout, "\n");                                 \
		(void)fflush(stdout);                                        \
	} while (0)

/**
 * \brief Print a hex dump of a buffer to stdout.
 *
 * Formats \p data as rows of 16 bytes (hex + ASCII) prefixed with a
 * colored severity tag and optional function name.
 *
 * \param[in] level     Severity tag string (e.g. "<inf>").
 * \param[in] color     ANSI color escape sequence.
 * \param[in] data      Pointer to the buffer to dump.
 * \param     length    Number of bytes in \p data.
 * \param[in] text      Descriptive text printed before the hex dump.
 * \param[in] func      Calling function name, or NULL to omit.
 */
static inline void edhoc_log_hexdump_impl(const char *level, const char *color,
					  const uint8_t *data, size_t length,
					  const char *text, const char *func)
{
	if (data == NULL || length == 0) {
		return;
	}

	char timestamp[32];
	edhoc_log_get_timestamp(timestamp, sizeof(timestamp));

	(void)fflush(stdout);

	/* Print header with or without function name */
	if (func != NULL) {
		(void)fprintf(stdout,
			      "%s %s%s" ANSI_COLOR_RESET
			      " libedhoc: %s: %s\n\n",
			      timestamp, color, level, func, text);
	} else {
		(void)fprintf(stdout,
			      "%s %s%s" ANSI_COLOR_RESET " libedhoc: %s\n\n",
			      timestamp, color, level, text);
	}

	/* Print hexdump in rows of 16 bytes */
	for (size_t i = 0; i < length; i += 16) {
		/* Print offset with indentation matching Zephyr output */
		(void)fprintf(stdout, "                                   ");

		/* Print hex values */
		for (size_t j = 0; j < 16; j++) {
			if (i + j < length) {
				(void)fprintf(stdout, "%02x ", data[i + j]);
			} else {
				(void)fprintf(stdout, "   ");
			}
			/* Add extra space in the middle */
			if (j == 7) {
				(void)fprintf(stdout, " ");
			}
		}

		/* Print ASCII representation */
		(void)fprintf(stdout, "|");
		for (size_t j = 0; j < 16 && i + j < length; j++) {
			uint8_t c = data[i + j];
			(void)fprintf(stdout, "%c",
				      (c >= 32 && c <= 126) ? c : '.');
		}

		(void)fprintf(stdout, "|\n");
	}

	(void)fflush(stdout);
}

#define EDHOC_LOG_HEXDUMP_INF(data, length, text)                         \
	edhoc_log_hexdump_impl("<inf>", ANSI_COLOR_GREEN,                 \
			       (const uint8_t *)(data), (length), (text), \
			       NULL)

#define EDHOC_LOG_HEXDUMP_DBG(data, length, text)                         \
	edhoc_log_hexdump_impl("<dbg>", ANSI_COLOR_CYAN,                  \
			       (const uint8_t *)(data), (length), (text), \
			       __func__)

/* Types and type definitions ---------------------------------------------- */
/* Module interface variables and constants -------------------------------- */
/* Extern variables and constant declarations ------------------------------ */
/* Module interface function declarations ---------------------------------- */

#endif /* EDHOC_LOG_BACKEND_H */
