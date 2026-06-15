/**
 * \file    edhoc_backend_log.h
 * \author  Kamil Kielbasa
 * \brief   EDHOC pluggable logging backend facade.
 *
 *          Diagnostic messages inside the library are emitted through a small
 *          set of macros (\ref EDHOC_LOG_ERR, \ref EDHOC_LOG_WRN, ...) whose
 *          implementation is selected at build time by the preprocessor, so the
 *          same sources can target a hosted build or Zephyr RTOS without
 *          touching the call sites.
 *
 *          The active verbosity is chosen at build time by the integer
 *          \c CONFIG_LIBEDHOC_LOG_LEVEL. When a message's severity is below the
 *          configured level the corresponding macro expands to a no-op:
 *            - \c EDHOC_LOG_LEVEL_NONE (0, default) -- logging disabled,
 *            - \c EDHOC_LOG_LEVEL_ERR  (1)          -- errors only,
 *            - \c EDHOC_LOG_LEVEL_WRN  (2)          -- errors and warnings,
 *            - \c EDHOC_LOG_LEVEL_INF  (3)          -- + informational messages,
 *            - \c EDHOC_LOG_LEVEL_DBG  (4)          -- + debug messages.
 *
 *          The implementation is selected by the preprocessor:
 *            - on Zephyr (\c __ZEPHYR__) the macros delegate to the Zephyr
 *              logging subsystem (\c LOG_ERR, \c LOG_HEXDUMP_INF, ...),
 *            - on every other platform a self-contained hosted backend prints
 *              timestamped, colour-coded messages to \c stdout / \c stderr.
 *
 * \copyright Copyright (c) 2026
 *
 */

/* Header guard ------------------------------------------------------------ */
#ifndef EDHOC_BACKEND_LOG_H
#define EDHOC_BACKEND_LOG_H

/* Defines ----------------------------------------------------------------- */

/** \defgroup edhoc-backend-log EDHOC logging backend
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

/*
 * The verbosity is selected by the integer CONFIG_LIBEDHOC_LOG_LEVEL. On Zephyr
 * its value is derived from the LIBEDHOC_LOG_LEVEL_CHOICE Kconfig choice; on
 * every other build it is passed directly, e.g. -DCONFIG_LIBEDHOC_LOG_LEVEL=4.
 * When it is not defined logging is disabled by default.
 */
#ifndef CONFIG_LIBEDHOC_LOG_LEVEL
#define CONFIG_LIBEDHOC_LOG_LEVEL EDHOC_LOG_LEVEL_NONE
#endif /* default log level */

/* Types and type definitions ---------------------------------------------- */

#ifdef __DOXYGEN__

/**
 * \brief Log an error message (printf-style).
 *
 * Active when \c CONFIG_LIBEDHOC_LOG_LEVEL >= \ref EDHOC_LOG_LEVEL_ERR,
 * otherwise expands to a no-op. On Zephyr it maps to \c LOG_ERR; on a hosted
 * build it prints a timestamped, colour-coded line to \c stderr.
 */
#define EDHOC_LOG_ERR(...)

/**
 * \brief Log a warning message (printf-style).
 *
 * Active when \c CONFIG_LIBEDHOC_LOG_LEVEL >= \ref EDHOC_LOG_LEVEL_WRN,
 * otherwise expands to a no-op. On Zephyr it maps to \c LOG_WRN; on a hosted
 * build it prints a timestamped, colour-coded line to \c stdout.
 */
#define EDHOC_LOG_WRN(...)

/**
 * \brief Log an informational message (printf-style).
 *
 * Active when \c CONFIG_LIBEDHOC_LOG_LEVEL >= \ref EDHOC_LOG_LEVEL_INF,
 * otherwise expands to a no-op. On Zephyr it maps to \c LOG_INF; on a hosted
 * build it prints a timestamped, colour-coded line to \c stdout.
 */
#define EDHOC_LOG_INF(...)

/**
 * \brief Log a debug message (printf-style).
 *
 * Active when \c CONFIG_LIBEDHOC_LOG_LEVEL >= \ref EDHOC_LOG_LEVEL_DBG,
 * otherwise expands to a no-op. On Zephyr it maps to \c LOG_DBG; on a hosted
 * build it prints a timestamped, colour-coded line (including the calling
 * function name) to \c stdout.
 */
#define EDHOC_LOG_DBG(...)

/**
 * \brief Hex-dump \p data with an informational header.
 *
 * Active when \c CONFIG_LIBEDHOC_LOG_LEVEL >= \ref EDHOC_LOG_LEVEL_INF,
 * otherwise expands to a no-op.
 *
 * \param data     Pointer to the buffer to dump.
 * \param length   Number of bytes.
 * \param text     Descriptive text printed before the hex dump.
 */
#define EDHOC_LOG_HEXDUMP_INF(data, length, text)

/**
 * \brief Hex-dump \p data with a debug header.
 *
 * Active when \c CONFIG_LIBEDHOC_LOG_LEVEL >= \ref EDHOC_LOG_LEVEL_DBG,
 * otherwise expands to a no-op.
 *
 * \param data     Pointer to the buffer to dump.
 * \param length   Number of bytes.
 * \param text     Descriptive text printed before the hex dump.
 */
#define EDHOC_LOG_HEXDUMP_DBG(data, length, text)

#else /* !__DOXYGEN__ */

#if defined(__ZEPHYR__)

#include <zephyr/logging/log.h>

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

#else /* !__ZEPHYR__ -- hosted backend */

#include <stdio.h>
#include <stdint.h>
#include <string.h>
#include <time.h>
#include <sys/time.h>

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

#endif /* __ZEPHYR__ */

/*
 * Compile-time level gating. The backend above always defines every macro;
 * here each one is replaced by a no-op when CONFIG_LIBEDHOC_LOG_LEVEL is below
 * its severity, so disabled call sites compile out completely.
 */
#if CONFIG_LIBEDHOC_LOG_LEVEL < EDHOC_LOG_LEVEL_ERR
#undef EDHOC_LOG_ERR
#define EDHOC_LOG_ERR(...) \
	do {               \
	} while (0)
#endif

#if CONFIG_LIBEDHOC_LOG_LEVEL < EDHOC_LOG_LEVEL_WRN
#undef EDHOC_LOG_WRN
#define EDHOC_LOG_WRN(...) \
	do {               \
	} while (0)
#endif

#if CONFIG_LIBEDHOC_LOG_LEVEL < EDHOC_LOG_LEVEL_INF
#undef EDHOC_LOG_INF
#undef EDHOC_LOG_HEXDUMP_INF
#define EDHOC_LOG_INF(...) \
	do {               \
	} while (0)
#define EDHOC_LOG_HEXDUMP_INF(data, length, text) \
	do {                                      \
	} while (0)
#endif

#if CONFIG_LIBEDHOC_LOG_LEVEL < EDHOC_LOG_LEVEL_DBG
#undef EDHOC_LOG_DBG
#undef EDHOC_LOG_HEXDUMP_DBG
#define EDHOC_LOG_DBG(...) \
	do {               \
	} while (0)
#define EDHOC_LOG_HEXDUMP_DBG(data, length, text) \
	do {                                      \
	} while (0)
#endif

#endif /* !__DOXYGEN__ */

/**@}*/

/* Module interface variables and constants -------------------------------- */
/* Extern variables and constant declarations ------------------------------ */
/* Module interface function declarations ---------------------------------- */

#endif /* EDHOC_BACKEND_LOG_H */
