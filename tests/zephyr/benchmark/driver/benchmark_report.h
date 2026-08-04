/**
 * \file    benchmark_report.h
 * \author  Kamil Kielbasa
 * \brief   Per-phase timing accumulation and JSON reporting for the EDHOC
 *          handshake benchmark.
 *
 * \copyright Copyright (c) 2026
 *
 */

/* Header guard ------------------------------------------------------------ */
#ifndef BENCHMARK_REPORT_H
#define BENCHMARK_REPORT_H

/* Include files ----------------------------------------------------------- */

/* Standard library headers: */
#include <stddef.h>
#include <stdint.h>

/* Types and type definitions ---------------------------------------------- */

/**
 * \brief EDHOC handshake phases timed individually.
 */
enum benchmark_phase {
	BENCHMARK_PHASE_MESSAGE_1_COMPOSE,
	BENCHMARK_PHASE_MESSAGE_1_PROCESS,
	BENCHMARK_PHASE_MESSAGE_2_COMPOSE,
	BENCHMARK_PHASE_MESSAGE_2_PROCESS,
	BENCHMARK_PHASE_MESSAGE_3_COMPOSE,
	BENCHMARK_PHASE_MESSAGE_3_PROCESS,
	BENCHMARK_PHASE_MESSAGE_4_COMPOSE,
	BENCHMARK_PHASE_MESSAGE_4_PROCESS,
	BENCHMARK_PHASE_COUNT,
};

/**
 * \brief Running min / max / sum of nanosecond samples for one phase.
 */
struct benchmark_stats {
	uint64_t sum_ns;
	uint64_t min_ns;
	uint64_t max_ns;
	size_t samples;
};

/**
 * \brief One cipher suite's benchmark result across all iterations.
 */
struct benchmark_result {
	const char *suite_name;
	int suite_id;
	size_t iterations;
	struct benchmark_stats phase[BENCHMARK_PHASE_COUNT];
	struct benchmark_stats total;
};

/* Module interface function declarations ---------------------------------- */

/**
 * \brief Monotonic timestamp in nanoseconds for phase timing.
 *
 *        On the POSIX arch (native_sim) this is the host monotonic clock, so
 *        it measures real CPU time; the Zephyr cycle counter would only reflect
 *        simulated time (zero for pure computation). On real hardware it is the
 *        kernel cycle counter.
 *
 * \return Monotonic time in nanoseconds.
 */
uint64_t benchmark_timestamp_ns(void);

/**
 * \brief Reset a result for a fresh cipher suite run.
 *
 * \param[out] result           Result to initialise.
 * \param[in] suite_name        Human-readable suite label.
 * \param suite_id              IANA cipher suite identifier.
 */
void benchmark_result_init(struct benchmark_result *result,
			   const char *suite_name, int suite_id);

/**
 * \brief Add one phase timing sample.
 *
 * \param[in,out] result        Result to update.
 * \param phase                 Which phase the sample belongs to.
 * \param nanoseconds           Elapsed time of the sample in nanoseconds.
 */
void benchmark_result_add(struct benchmark_result *result,
			  enum benchmark_phase phase, uint64_t nanoseconds);

/**
 * \brief Add one full-handshake (all phases) timing sample.
 *
 * \param[in,out] result        Result to update.
 * \param nanoseconds           Elapsed time of the whole handshake in ns.
 */
void benchmark_result_add_total(struct benchmark_result *result,
				uint64_t nanoseconds);

/**
 * \brief Emit the result as a single-line-per-object JSON report.
 *
 *        Printed to the console (captured by twister) and, on native targets
 *        with host stdio, also appended to \c edhoc_benchmark.json so CI can
 *        publish the raw numbers as an artifact.
 *
 * \param[in] result            Result to report.
 */
void benchmark_report_emit(const struct benchmark_result *result);

#endif /* BENCHMARK_REPORT_H */
