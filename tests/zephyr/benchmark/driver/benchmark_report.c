/**
 * \file    benchmark_report.c
 * \author  Kamil Kielbasa
 * \brief   Implementation of the EDHOC handshake benchmark reporting.
 *
 * \copyright Copyright (c) 2026
 *
 */

/* Include files ----------------------------------------------------------- */

/* Benchmark headers: */
#include "benchmark_report.h"

/* Zephyr headers: */
#include <zephyr/kernel.h>
#include <zephyr/sys/printk.h>

/* Standard library headers: */
#include <stdint.h>
#include <stddef.h>
#if defined(CONFIG_ARCH_POSIX)
#include <time.h>
#endif

/* Module defines ---------------------------------------------------------- */
/* Module types and type definitions --------------------------------------- */
/* Module interface variables and constants -------------------------------- */
/* Static variables and constants ------------------------------------------ */

static const char *const benchmark_json_begin =
	"===EDHOC_BENCHMARK_JSON_BEGIN===";
static const char *const benchmark_json_end = "===EDHOC_BENCHMARK_JSON_END===";

static const char *const benchmark_phase_name[BENCHMARK_PHASE_COUNT] = {
	[BENCHMARK_PHASE_MESSAGE_1_COMPOSE] = "message_1_compose",
	[BENCHMARK_PHASE_MESSAGE_1_PROCESS] = "message_1_process",
	[BENCHMARK_PHASE_MESSAGE_2_COMPOSE] = "message_2_compose",
	[BENCHMARK_PHASE_MESSAGE_2_PROCESS] = "message_2_process",
	[BENCHMARK_PHASE_MESSAGE_3_COMPOSE] = "message_3_compose",
	[BENCHMARK_PHASE_MESSAGE_3_PROCESS] = "message_3_process",
	[BENCHMARK_PHASE_MESSAGE_4_COMPOSE] = "message_4_compose",
	[BENCHMARK_PHASE_MESSAGE_4_PROCESS] = "message_4_process",
};

/* Static function declarations -------------------------------------------- */

static void benchmark_stats_reset(struct benchmark_stats *stats);
static void benchmark_stats_add(struct benchmark_stats *stats,
				uint64_t nanoseconds);
static uint64_t benchmark_stats_average(const struct benchmark_stats *stats);

/* Static function definitions --------------------------------------------- */

static void benchmark_stats_reset(struct benchmark_stats *stats)
{
	stats->sum_ns = 0;
	stats->min_ns = UINT64_MAX;
	stats->max_ns = 0;
	stats->samples = 0;
}

static void benchmark_stats_add(struct benchmark_stats *stats,
				uint64_t nanoseconds)
{
	stats->sum_ns += nanoseconds;
	stats->samples += 1;

	if (nanoseconds < stats->min_ns) {
		stats->min_ns = nanoseconds;
	}

	if (nanoseconds > stats->max_ns) {
		stats->max_ns = nanoseconds;
	}
}

static uint64_t benchmark_stats_average(const struct benchmark_stats *stats)
{
	if (0 == stats->samples) {
		return 0;
	}

	return stats->sum_ns / stats->samples;
}

/* Module interface function definitions ----------------------------------- */

uint64_t benchmark_timestamp_ns(void)
{
#if defined(CONFIG_ARCH_POSIX)
	/* native_sim: the host monotonic clock measures real CPU time. */
	struct timespec now = { 0 };

	(void)clock_gettime(CLOCK_MONOTONIC, &now);

	return (uint64_t)now.tv_sec * NSEC_PER_SEC + (uint64_t)now.tv_nsec;
#else
	/* Real hardware: the kernel cycle counter. */
	return k_cyc_to_ns_floor64(k_cycle_get_32());
#endif
}

void benchmark_result_init(struct benchmark_result *result,
			   const char *suite_name, int suite_id)
{
	result->suite_name = suite_name;
	result->suite_id = suite_id;
	result->iterations = 0;

	for (size_t i = 0; i < BENCHMARK_PHASE_COUNT; ++i) {
		benchmark_stats_reset(&result->phase[i]);
	}

	benchmark_stats_reset(&result->total);
}

void benchmark_result_add(struct benchmark_result *result,
			  enum benchmark_phase phase, uint64_t nanoseconds)
{
	benchmark_stats_add(&result->phase[phase], nanoseconds);
}

void benchmark_result_add_total(struct benchmark_result *result,
				uint64_t nanoseconds)
{
	benchmark_stats_add(&result->total, nanoseconds);
	result->iterations += 1;
}

void benchmark_report_emit(const struct benchmark_result *result)
{
	printk("%s\n", benchmark_json_begin);
	printk("{\n");
	printk("  \"benchmark\": \"edhoc_handshake\",\n");
	printk("  \"cipher_suite\": %d,\n", result->suite_id);
	printk("  \"cipher_suite_name\": \"%s\",\n", result->suite_name);
	printk("  \"method\": 0,\n");
	printk("  \"credentials\": \"x5chain\",\n");
	printk("  \"iterations\": %zu,\n", result->iterations);
	printk("  \"unit\": \"ns\",\n");
	printk("  \"phases\": {\n");

	for (size_t i = 0; i < BENCHMARK_PHASE_COUNT; ++i) {
		const struct benchmark_stats *stats = &result->phase[i];
		const char *separator = (i + 1 < BENCHMARK_PHASE_COUNT) ? "," :
									  "";

		printk("    \"%s\": { \"avg\": %llu, \"min\": %llu, \"max\": %llu }%s\n",
		       benchmark_phase_name[i], benchmark_stats_average(stats),
		       stats->min_ns, stats->max_ns, separator);
	}

	printk("  },\n");
	printk("  \"total_handshake\": { \"avg\": %llu, \"min\": %llu, \"max\": %llu }\n",
	       benchmark_stats_average(&result->total), result->total.min_ns,
	       result->total.max_ns);
	printk("}\n");
	printk("%s\n", benchmark_json_end);
}
