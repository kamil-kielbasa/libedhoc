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
#include "backend_cbor_sig_structure_encode.h"
#include "zcbor_print.h"

#if DEFAULT_MAX_QTY != 3
#error "The type file was generated with a different default_max_qty than this file"
#endif

static bool encode_sig_structure(zcbor_state_t *state, const struct sig_structure *input);


static bool encode_sig_structure(
		zcbor_state_t *state, const struct sig_structure *input)
{
	zcbor_log("%s\r\n", __func__);
	struct zcbor_string tmp_str;

	bool tmp_result = (((zcbor_list_start_encode(state, 4) && ((((zcbor_tstr_encode(state, ((tmp_str.value = (uint8_t *)"Signature1", tmp_str.len = sizeof("Signature1") - 1, &tmp_str)))))
	&& ((zcbor_bstr_encode(state, (&(*input).sig_structure_protected))))
	&& ((zcbor_bstr_encode(state, (&(*input).sig_structure_external_aad))))
	&& ((zcbor_bstr_encode(state, (&(*input).sig_structure_payload))))) || (zcbor_list_map_end_force_encode(state), false)) && zcbor_list_end_encode(state, 4))));

	if (!tmp_result) {
		zcbor_trace_file(state);
		zcbor_log("%s error: %s\r\n", __func__, zcbor_error_str(zcbor_peek_error(state)));
	} else {
		zcbor_log("%s success\r\n", __func__);
	}

	return tmp_result;
}



int cbor_encode_sig_structure(
		uint8_t *payload, size_t payload_len,
		const struct sig_structure *input,
		size_t *payload_len_out)
{
	zcbor_state_t states[3];

	return zcbor_entry_function(payload, payload_len, (void *)input, payload_len_out, states,
		(zcbor_decoder_t *)encode_sig_structure, sizeof(states) / sizeof(zcbor_state_t), 1);
}
