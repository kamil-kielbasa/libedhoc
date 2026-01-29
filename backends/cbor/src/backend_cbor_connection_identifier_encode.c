/*
 * Generated using zcbor version 0.9.1-9b07780
 * https://github.com/NordicSemiconductor/zcbor
 * at: 2026-01-27 07:10:10
 * Generated with a --default-max-qty of 3
 */

#include <stdint.h>
#include <stdbool.h>
#include <stddef.h>
#include <string.h>
#include "zcbor_encode.h"
#include "backend_cbor_connection_identifier_encode.h"
#include "zcbor_print.h"

#if DEFAULT_MAX_QTY != 3
#error "The type file was generated with a different default_max_qty than this file"
#endif

#define log_result(state, result, func) do { \
	if (!result) { \
		zcbor_trace_file(state); \
		zcbor_log("%s error: %s\r\n", func, zcbor_error_str(zcbor_peek_error(state))); \
	} else { \
		zcbor_log("%s success\r\n", func); \
	} \
} while(0)

static bool encode_connection_identifier(zcbor_state_t *state, const struct connection_identifier_r *input);


static bool encode_connection_identifier(
		zcbor_state_t *state, const struct connection_identifier_r *input)
{
	zcbor_log("%s\r\n", __func__);

	bool res = (((((*input).connection_identifier_choice == connection_identifier_bstr_c) ? ((zcbor_bstr_encode(state, (&(*input).connection_identifier_bstr))))
	: (((*input).connection_identifier_choice == connection_identifier_int_c) ? (((((*input).connection_identifier_int >= -24)
	&& ((*input).connection_identifier_int <= 23)) || (zcbor_error(state, ZCBOR_ERR_WRONG_RANGE), false))
	&& (zcbor_int32_encode(state, (&(*input).connection_identifier_int))))
	: false))));

	log_result(state, res, __func__);
	return res;
}



int cbor_encode_connection_identifier(
		uint8_t *payload, size_t payload_len,
		const struct connection_identifier_r *input,
		size_t *payload_len_out)
{
	zcbor_state_t states[3];

	return zcbor_entry_function(payload, payload_len, (void *)input, payload_len_out, states,
		(zcbor_decoder_t *)encode_connection_identifier, sizeof(states) / sizeof(zcbor_state_t), 1);
}

