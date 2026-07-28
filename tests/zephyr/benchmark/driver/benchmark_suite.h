/**
 * \file    benchmark_suite.h
 * \author  Kamil Kielbasa
 * \brief   Benchmark harness: cipher-suite case descriptor and runner.
 *
 *          A per-suite test (benchmark_suite_*.c) fills in a \ref
 *          benchmark_case — its identities, method and connection identifiers —
 *          and hands it to \ref benchmark_run_case, which drives the timed
 *          EDHOC handshake and emits the JSON report. Every suite lives in its
 *          own translation unit because each test-vector header defines the
 *          same credential symbol names (\c CRED_I, \c SK_I, \c PK_I, ...), so
 *          two of them cannot be compiled into a single file.
 *
 * \copyright Copyright (c) 2026
 *
 */

/* Header guard ------------------------------------------------------------ */
#ifndef BENCHMARK_SUITE_H
#define BENCHMARK_SUITE_H

/* Include files ----------------------------------------------------------- */

/* Benchmark harness building blocks: */
#include "benchmark_credentials.h"
#include "benchmark_ead.h"

/* EDHOC headers: */
#include <edhoc/edhoc.h>
#include <edhoc/cipher_suite.h>

/* Standard library headers: */
#include <stddef.h>

/* Types and type definitions ---------------------------------------------- */

/**
 * \brief One EDHOC endpoint of a case.
 *
 *        A pointer to this structure is bound to the context as its
 *        \c user_context, so it is the single object every credential and EAD
 *        callback receives: \ref benchmark_credentials_fetch presents \c own,
 *        \ref benchmark_credentials_verify authenticates \c peer, and the EAD
 *        callbacks read \c ead. Built internally by \ref benchmark_run_case.
 */
struct benchmark_endpoint {
	/** Connection identifier this endpoint advertises. */
	struct edhoc_connection_id connection_id;
	/** Identity this endpoint presents (fetch). */
	const struct benchmark_identity *own;
	/** Identity this endpoint must verify from the peer (verify). */
	const struct benchmark_identity *peer;
	/** EAD tokens for the whole handshake, or NULL to bind no EAD. */
	const struct benchmark_ead *ead;
};

/**
 * \brief One benchmark case: everything needed to run a single cipher suite.
 *
 *        Everything that varies between cases is a field here, so the runner
 *        bakes in nothing: the method, connection identifiers and identities
 *        all come from the caller.
 */
struct benchmark_case {
	/** Human-readable cipher suite label (for the JSON report). */
	const char *name;
	/** IANA cipher suite identifier to benchmark. */
	enum edhoc_cipher_suite_id suite_id;

	/** EDHOC methods offered by both peers. */
	const enum edhoc_method *methods;
	/** Number of entries in \p methods. */
	size_t methods_count;

	/** Connection identifier the Initiator advertises. */
	struct edhoc_connection_id initiator_connection_id;
	/** Connection identifier the Responder advertises. */
	struct edhoc_connection_id responder_connection_id;

	/** Initiator identity (presented on fetch, verified by the peer). */
	const struct benchmark_identity *initiator;
	/** Responder identity (presented on fetch, verified by the peer). */
	const struct benchmark_identity *responder;
};

/* Module interface function declarations ---------------------------------- */

/**
 * \brief Benchmark one cipher suite case: run the full EDHOC handshake for a
 *        fixed number of iterations and emit the JSON report.
 *
 * \param[in] benchmark_case    The case to run.
 */
void benchmark_run_case(const struct benchmark_case *benchmark_case);

#endif /* BENCHMARK_SUITE_H */
