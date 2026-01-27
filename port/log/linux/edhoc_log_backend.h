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

#define ANSI_COLOR_RED "\x1b[31m"
#define ANSI_COLOR_YELLOW "\x1b[33m"
#define ANSI_COLOR_GREEN "\x1b[32m"
#define ANSI_COLOR_CYAN "\x1b[36m"
#define ANSI_COLOR_RESET "\x1b[0m"

static inline void edhoc_log_get_timestamp(char *buffer, size_t size)
{
	struct timeval tv;
	struct tm *tm_info;

	gettimeofday(&tv, NULL);
	tm_info = localtime(&tv.tv_sec);

	const int milliseconds = (int)(tv.tv_usec / 1000);
	const int microseconds = (int)(tv.tv_usec % 1000);

	snprintf(buffer, size, "[%02d:%02d:%02d.%03d,%03d]", tm_info->tm_hour,
		 tm_info->tm_min, tm_info->tm_sec, milliseconds, microseconds);
}

#define EDHOC_LOG_ERR(...)                                              \
	do {                                                            \
		char timestamp[32];                                     \
		edhoc_log_get_timestamp(timestamp, sizeof(timestamp));  \
		fflush(stdout);                                         \
		fprintf(stderr,                                         \
			"\n%s " ANSI_COLOR_RED "<err>" ANSI_COLOR_RESET \
			" libedhoc: ",                                  \
			timestamp);                                     \
		fprintf(stderr, __VA_ARGS__);                           \
		fprintf(stderr, "\n");                                  \
		fflush(stderr);                                         \
	} while (0)

#define EDHOC_LOG_WRN(...)                                                 \
	do {                                                               \
		char timestamp[32];                                        \
		edhoc_log_get_timestamp(timestamp, sizeof(timestamp));     \
		fflush(stdout);                                            \
		fprintf(stdout,                                            \
			"\n%s " ANSI_COLOR_YELLOW "<wrn>" ANSI_COLOR_RESET \
			" libedhoc: ",                                     \
			timestamp);                                        \
		fprintf(stdout, __VA_ARGS__);                              \
		fprintf(stdout, "\n");                                     \
		fflush(stdout);                                            \
	} while (0)

#define EDHOC_LOG_INF(...)                                                \
	do {                                                              \
		char timestamp[32];                                       \
		edhoc_log_get_timestamp(timestamp, sizeof(timestamp));    \
		fflush(stdout);                                           \
		fprintf(stdout,                                           \
			"\n%s " ANSI_COLOR_GREEN "<inf>" ANSI_COLOR_RESET \
			" libedhoc: ",                                    \
			timestamp);                                       \
		fprintf(stdout, __VA_ARGS__);                             \
		fprintf(stdout, "\n");                                    \
		fflush(stdout);                                           \
	} while (0)

#define EDHOC_LOG_DBG(...)                                               \
	do {                                                             \
		char timestamp[32];                                      \
		edhoc_log_get_timestamp(timestamp, sizeof(timestamp));   \
		fflush(stdout);                                          \
		fprintf(stdout,                                          \
			"\n%s " ANSI_COLOR_CYAN "<dbg>" ANSI_COLOR_RESET \
			" libedhoc: ",                                   \
			timestamp);                                      \
		fprintf(stdout, __VA_ARGS__);                            \
		fprintf(stdout, "\n");                                   \
		fflush(stdout);                                          \
	} while (0)

static inline void edhoc_log_hexdump_impl(const char *level, const char *color,
					  const uint8_t *data, size_t length,
					  const char *text)
{
	if (data == NULL || length == 0) {
		return;
	}

	char timestamp[32];
	edhoc_log_get_timestamp(timestamp, sizeof(timestamp));

	fflush(stdout);

	/* Print header with Zephyr-style format */
	fprintf(stdout, "%s %s%s" ANSI_COLOR_RESET " libedhoc: %s\n\n",
		timestamp, color, level, text);

	/* Print hexdump in rows of 16 bytes */
	for (size_t i = 0; i < length; i += 16) {
		/* Print offset with indentation matching Zephyr output */
		fprintf(stdout, "                                   ");

		/* Print hex values */
		for (size_t j = 0; j < 16; j++) {
			if (i + j < length) {
				fprintf(stdout, "%02x ", data[i + j]);
			} else {
				fprintf(stdout, "   ");
			}
			/* Add extra space in the middle */
			if (j == 7) {
				fprintf(stdout, " ");
			}
		}

		/* Print ASCII representation */
		fprintf(stdout, "|");
		for (size_t j = 0; j < 16 && i + j < length; j++) {
			uint8_t c = data[i + j];
			fprintf(stdout, "%c", (c >= 32 && c <= 126) ? c : '.');
		}

		/* Last line: add closing | and spaces but no newline */
		fprintf(stdout, "|\n");
	}

	fflush(stdout);
}

#define EDHOC_LOG_HEXDUMP_INF(data, length, text)         \
	edhoc_log_hexdump_impl("<inf>", ANSI_COLOR_GREEN, \
			       (const uint8_t *)(data), (length), (text))

#define EDHOC_LOG_HEXDUMP_DBG(data, length, text)        \
	edhoc_log_hexdump_impl("<dbg>", ANSI_COLOR_CYAN, \
			       (const uint8_t *)(data), (length), (text))

/* Types and type definitions ---------------------------------------------- */
/* Module interface variables and constants -------------------------------- */
/* Extern variables and constant declarations ------------------------------ */
/* Module interface function declarations ---------------------------------- */

#endif /* EDHOC_LOG_BACKEND_H */
