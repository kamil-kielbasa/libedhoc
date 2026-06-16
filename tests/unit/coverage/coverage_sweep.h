/**
 * \file    coverage_sweep.h
 * \author  Kamil Kielbasa
 * \brief   Expected outcomes for mock fail-point coverage sweeps.
 *
 * \copyright Copyright (c) 2026
 *
 */

/* Header guard ------------------------------------------------------------ */
#ifndef COVERAGE_SWEEP_H
#define COVERAGE_SWEEP_H

/* Include files ----------------------------------------------------------- */
#include <stdbool.h>

#include <unity.h>

/* Defines ----------------------------------------------------------------- */
/* Types and type definitions ---------------------------------------------- */
/* Module interface variables and constants -------------------------------- */
/* Extern variables and constant declarations ------------------------------ */
/* Module interface function declarations ---------------------------------- */

static inline void coverage_assert_sweep_result(int ret, bool must_fail)
{
	if (must_fail) {
		TEST_ASSERT_NOT_EQUAL(EDHOC_SUCCESS, ret);
	} else {
		TEST_ASSERT_EQUAL(EDHOC_SUCCESS, ret);
	}
}

static inline bool coverage_msg1_compose_must_fail(int fail_pt)
{
	return fail_pt >= 1 && fail_pt <= 4;
}

static inline bool coverage_msg1_process_must_fail(int fail_pt)
{
	return fail_pt == 1;
}

static inline bool coverage_msg2_compose_m0_must_fail(int fail_pt)
{
	return fail_pt >= 4 && fail_pt <= 15;
}

static inline bool coverage_msg2_compose_m0_high_must_fail(int fail_pt)
{
	(void)fail_pt;
	return false;
}

static inline bool coverage_msg2_compose_method_sweep_must_fail(int fail_pt)
{
	return fail_pt >= 4 && fail_pt <= 12;
}

static inline bool coverage_msg2_process_m0_must_fail(int fail_pt)
{
	return fail_pt >= 1 && fail_pt <= 13;
}

static inline bool coverage_msg2_process_m3_must_fail(int fail_pt)
{
	return fail_pt >= 1 && fail_pt <= 17;
}

static inline bool coverage_msg2_process_method_sweep_must_fail(int fail_pt)
{
	return fail_pt >= 1 && fail_pt <= 17;
}

static inline bool coverage_msg2_compose_method3_high_must_fail(int fail_pt)
{
	return fail_pt >= 13 && fail_pt <= 19;
}

static inline bool coverage_msg2_compose_gap_must_fail(int fail_pt)
{
	(void)fail_pt;
	return false;
}

static inline bool coverage_msg2_process_gap_must_fail(int fail_pt)
{
	(void)fail_pt;
	return false;
}

static inline bool coverage_msg2_compose_extended_must_fail(int fail_pt)
{
	return fail_pt >= 1 && fail_pt <= 15;
}

static inline bool coverage_msg2_compose_bstr_cid_must_fail(int fail_pt)
{
	return fail_pt >= 1 && fail_pt <= 15;
}

static inline bool coverage_msg2_process_bstr_cid_must_fail(int fail_pt)
{
	return fail_pt >= 1 && fail_pt <= 13;
}

static inline bool coverage_msg3_compose_sweep_must_fail(int fail_pt)
{
	return fail_pt >= 1 && fail_pt <= 12;
}

static inline bool coverage_msg3_compose_method_must_fail(int fail_pt)
{
	return fail_pt >= 1 && fail_pt <= 16;
}

static inline bool coverage_msg3_process_method_must_fail(int fail_pt)
{
	return fail_pt >= 1 && fail_pt <= 16;
}

static inline bool coverage_msg3_process_sweep_must_fail(int fail_pt)
{
	return fail_pt >= 1 && fail_pt <= 12;
}

static inline bool coverage_msg3_compose_extended_must_fail(int fail_pt)
{
	(void)fail_pt;
	return false;
}

static inline bool coverage_msg3_process_extended_must_fail(int fail_pt)
{
	(void)fail_pt;
	return false;
}

static inline bool coverage_msg3_compose_bstr_cid_must_fail(int fail_pt)
{
	return fail_pt >= 1 && fail_pt <= 12;
}

static inline bool coverage_msg3_gap_must_fail(int fail_pt)
{
	(void)fail_pt;
	return false;
}

static inline bool coverage_msg4_compose_sweep_must_fail(int fail_pt)
{
	return fail_pt >= 1 && fail_pt <= 7;
}

static inline bool coverage_msg4_compose_method_must_fail(int fail_pt)
{
	return fail_pt >= 1 && fail_pt <= 7;
}

static inline bool coverage_msg4_process_sweep_must_fail(int fail_pt)
{
	return fail_pt >= 1 && fail_pt <= 6;
}

static inline bool coverage_msg4_process_method_must_fail(int fail_pt)
{
	return fail_pt >= 1 && fail_pt <= 6;
}

static inline bool coverage_msg4_compose_extended_must_fail(int fail_pt)
{
	(void)fail_pt;
	return false;
}

static inline bool coverage_msg4_process_extended_must_fail(int fail_pt)
{
	(void)fail_pt;
	return false;
}

static inline bool coverage_msg4_compose_gap_must_fail(int fail_pt)
{
	(void)fail_pt;
	return false;
}

static inline bool coverage_msg4_process_gap_must_fail(int fail_pt)
{
	(void)fail_pt;
	return false;
}

static inline bool coverage_msg4_gap_must_fail(int fail_pt)
{
	return coverage_msg4_compose_gap_must_fail(fail_pt);
}

static inline bool coverage_oscore_export_must_fail(int fail_pt)
{
	return fail_pt >= 1 && fail_pt <= 10;
}

static inline bool coverage_key_update_must_fail(int fail_pt)
{
	return fail_pt >= 1 && fail_pt <= 4;
}

static inline bool coverage_oscore_export_extended_must_fail(int fail_pt)
{
	return fail_pt >= 1 && fail_pt <= 10;
}

#endif /* COVERAGE_SWEEP_H */
