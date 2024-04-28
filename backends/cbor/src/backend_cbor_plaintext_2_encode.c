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
#include "backend_cbor_plaintext_2_encode.h"

#if DEFAULT_MAX_QTY != 3
#error "The type file was generated with a different default_max_qty than this file"
#endif

static bool encode_repeated_map_kid(zcbor_state_t *state, const struct map_kid_ *input);
static bool encode_repeated_map_x5bag(zcbor_state_t *state, const struct map_x5bag *input);
static bool encode_repeated_map_x5chain(zcbor_state_t *state, const struct map_x5chain *input);
static bool encode_repeated_map_x5t(zcbor_state_t *state, const struct map_x5t_ *input);
static bool encode_map(zcbor_state_t *state, const struct map *input);
static bool encode_repeated_ead_x(zcbor_state_t *state, const struct ead_x *input);
static bool encode_ead_x(zcbor_state_t *state, const struct ead_x_ *input);
static bool encode_plaintext_2(zcbor_state_t *state, const struct plaintext_2 *input);


static bool encode_repeated_map_kid(
		zcbor_state_t *state, const struct map_kid_ *input)
{
	zcbor_print("%s\r\n", __func__);

	bool tmp_result = ((((zcbor_uint32_put(state, (4))))
	&& (((*input)._map_kid_choice == _map_kid_int) ? ((zcbor_int32_encode(state, (&(*input)._map_kid_int))))
	: (((*input)._map_kid_choice == _map_kid_bstr) ? ((zcbor_bstr_encode(state, (&(*input)._map_kid_bstr))))
	: false))));

	if (!tmp_result)
		zcbor_trace();

	return tmp_result;
}

static bool encode_repeated_map_x5bag(
		zcbor_state_t *state, const struct map_x5bag *input)
{
	zcbor_print("%s\r\n", __func__);

	bool tmp_result = ((((zcbor_uint32_put(state, (32))))
	&& (zcbor_bstr_encode(state, (&(*input)._map_x5bag)))));

	if (!tmp_result)
		zcbor_trace();

	return tmp_result;
}

static bool encode_repeated_map_x5chain(
		zcbor_state_t *state, const struct map_x5chain *input)
{
	zcbor_print("%s\r\n", __func__);

	bool tmp_result = ((((zcbor_uint32_put(state, (33))))
	&& (zcbor_bstr_encode(state, (&(*input)._map_x5chain)))));

	if (!tmp_result)
		zcbor_trace();

	return tmp_result;
}

static bool encode_repeated_map_x5t(
		zcbor_state_t *state, const struct map_x5t_ *input)
{
	zcbor_print("%s\r\n", __func__);

	bool tmp_result = ((((zcbor_uint32_put(state, (34))))
	&& (zcbor_list_start_encode(state, 2) && ((((((*input)._map_x5t_alg_choice == _map_x5t_alg_int) ? ((zcbor_int32_encode(state, (&(*input)._map_x5t_alg_int))))
	: (((*input)._map_x5t_alg_choice == _map_x5t_alg_bstr) ? ((zcbor_bstr_encode(state, (&(*input)._map_x5t_alg_bstr))))
	: false)))
	&& ((zcbor_bstr_encode(state, (&(*input)._map_x5t_hash))))) || (zcbor_list_map_end_force_encode(state), false)) && zcbor_list_end_encode(state, 2))));

	if (!tmp_result)
		zcbor_trace();

	return tmp_result;
}

static bool encode_map(
		zcbor_state_t *state, const struct map *input)
{
	zcbor_print("%s\r\n", __func__);

	bool tmp_result = (((zcbor_map_start_encode(state, 4) && ((zcbor_present_encode(&((*input)._map_kid_present), (zcbor_encoder_t *)encode_repeated_map_kid, state, (&(*input)._map_kid))
	&& zcbor_present_encode(&((*input)._map_x5bag_present), (zcbor_encoder_t *)encode_repeated_map_x5bag, state, (&(*input)._map_x5bag))
	&& zcbor_present_encode(&((*input)._map_x5chain_present), (zcbor_encoder_t *)encode_repeated_map_x5chain, state, (&(*input)._map_x5chain))
	&& zcbor_present_encode(&((*input)._map_x5t_present), (zcbor_encoder_t *)encode_repeated_map_x5t, state, (&(*input)._map_x5t))) || (zcbor_list_map_end_force_encode(state), false)) && zcbor_map_end_encode(state, 4))));

	if (!tmp_result)
		zcbor_trace();

	return tmp_result;
}

static bool encode_repeated_ead_x(
		zcbor_state_t *state, const struct ead_x *input)
{
	zcbor_print("%s\r\n", __func__);

	bool tmp_result = (((((zcbor_int32_encode(state, (&(*input)._ead_x_ead_label))))
	&& zcbor_present_encode(&((*input)._ead_x_ead_value_present), (zcbor_encoder_t *)zcbor_bstr_encode, state, (&(*input)._ead_x_ead_value)))));

	if (!tmp_result)
		zcbor_trace();

	return tmp_result;
}

static bool encode_ead_x(
		zcbor_state_t *state, const struct ead_x_ *input)
{
	zcbor_print("%s\r\n", __func__);

	bool tmp_result = (zcbor_multi_encode_minmax(1, 3, &(*input)._ead_x_count, (zcbor_encoder_t *)encode_repeated_ead_x, state, (&(*input)._ead_x), sizeof(struct ead_x)));

	if (!tmp_result)
		zcbor_trace();

	return tmp_result;
}

static bool encode_plaintext_2(
		zcbor_state_t *state, const struct plaintext_2 *input)
{
	zcbor_print("%s\r\n", __func__);

	bool tmp_result = (((((((*input)._plaintext_2_C_R_choice == _plaintext_2_C_R_bstr) ? ((zcbor_bstr_encode(state, (&(*input)._plaintext_2_C_R_bstr))))
	: (((*input)._plaintext_2_C_R_choice == _plaintext_2_C_R_int) ? (((((*input)._plaintext_2_C_R_int >= -24)
	&& ((*input)._plaintext_2_C_R_int <= 23)) || (zcbor_error(state, ZCBOR_ERR_WRONG_RANGE), false))
	&& (zcbor_int32_encode(state, (&(*input)._plaintext_2_C_R_int))))
	: false)))
	&& ((((*input)._plaintext_2_ID_CRED_R_choice == _plaintext_2_ID_CRED_R_int) ? ((zcbor_int32_encode(state, (&(*input)._plaintext_2_ID_CRED_R_int))))
	: (((*input)._plaintext_2_ID_CRED_R_choice == _plaintext_2_ID_CRED_R_bstr) ? ((zcbor_bstr_encode(state, (&(*input)._plaintext_2_ID_CRED_R_bstr))))
	: (((*input)._plaintext_2_ID_CRED_R_choice == _plaintext_2_ID_CRED_R__map) ? ((encode_map(state, (&(*input)._plaintext_2_ID_CRED_R__map))))
	: false))))
	&& ((zcbor_bstr_encode(state, (&(*input)._plaintext_2_Signature_or_MAC_2))))
	&& zcbor_present_encode(&((*input)._plaintext_2_EAD_2_present), (zcbor_encoder_t *)encode_ead_x, state, (&(*input)._plaintext_2_EAD_2)))));

	if (!tmp_result)
		zcbor_trace();

	return tmp_result;
}



int cbor_encode_plaintext_2(
		uint8_t *payload, size_t payload_len,
		const struct plaintext_2 *input,
		size_t *payload_len_out)
{
	zcbor_state_t states[6];

	zcbor_new_state(states, sizeof(states) / sizeof(zcbor_state_t), payload, payload_len, 9);

	bool ret = encode_plaintext_2(states, input);

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
