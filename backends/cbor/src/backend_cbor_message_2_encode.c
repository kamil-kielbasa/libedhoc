/*
 * Generated using zcbor version 0.7.0
 * https://github.com/NordicSemiconductor/zcbor
 * Generated with a --default-max-qty of 3
 */

#include <stdint.h>
#include <stdbool.h>
#include <stddef.h>
#include <string.h>
#include "zcbor_encode.h"
#include "backend_cbor_message_2_encode.h"

#if DEFAULT_MAX_QTY != 3
#error "The type file was generated with a different default_max_qty than this file"
#endif

static bool encode_message_2(zcbor_state_t *state, const struct message_2 *input);


static bool encode_message_2(
		zcbor_state_t *state, const struct message_2 *input)
{
	zcbor_print("%s\r\n", __func__);

	bool tmp_result = (((((zcbor_bstr_encode(state, (&(*input)._message_2_G_Y_CIPHERTEXT_2))))
	&& ((((*input)._message_2_C_R_choice == _message_2_C_R_bstr) ? ((zcbor_bstr_encode(state, (&(*input)._message_2_C_R_bstr))))
	: (((*input)._message_2_C_R_choice == _message_2_C_R_int) ? (((((*input)._message_2_C_R_int >= -24)
	&& ((*input)._message_2_C_R_int <= 23)) || (zcbor_error(state, ZCBOR_ERR_WRONG_RANGE), false))
	&& (zcbor_int32_encode(state, (&(*input)._message_2_C_R_int))))
	: false))))));

	if (!tmp_result)
		zcbor_trace();

	return tmp_result;
}



int cbor_encode_message_2(
		uint8_t *payload, size_t payload_len,
		const struct message_2 *input,
		size_t *payload_len_out)
{
	zcbor_state_t states[3];

	zcbor_new_state(states, sizeof(states) / sizeof(zcbor_state_t), payload, payload_len, 2);

	bool ret = encode_message_2(states, input);

	if (ret && (payload_len_out != NULL)) {
		*payload_len_out = MIN(payload_len,
				(size_t)states[0].payload - (size_t)payload);
	}

	if (!ret) {
		int err = zcbor_pop_error(states);

		zcbor_print("Return error: %d\r\n", err);
		return (err == ZCBOR_SUCCESS) ? ZCBOR_ERR_UNKNOWN : err;
	}
	return ZCBOR_SUCCESS;
}
