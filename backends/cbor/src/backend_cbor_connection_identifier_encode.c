/*
 * Generated using zcbor version 0.8.1
 * https://github.com/NordicSemiconductor/zcbor
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

static bool encode_connection_identifier(zcbor_state_t *state, const struct connection_identifier_r *input);


static bool encode_connection_identifier(
		zcbor_state_t *state, const struct connection_identifier_r *input)
{
	zcbor_log("%s\r\n", __func__);

	bool tmp_result = (((((*input).connection_identifier_choice == connection_identifier_bstr_c) ? ((zcbor_bstr_encode(state, (&(*input).connection_identifier_bstr))))
	: (((*input).connection_identifier_choice == connection_identifier_int_c) ? (((((*input).connection_identifier_int >= -24)
	&& ((*input).connection_identifier_int <= 23)) || (zcbor_error(state, ZCBOR_ERR_WRONG_RANGE), false))
	&& (zcbor_int32_encode(state, (&(*input).connection_identifier_int))))
	: false))));

	if (!tmp_result) {
		zcbor_trace_file(state);
		zcbor_log("%s error: %s\r\n", __func__, zcbor_error_str(zcbor_peek_error(state)));
	} else {
		zcbor_log("%s success\r\n", __func__);
	}

	return tmp_result;
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
