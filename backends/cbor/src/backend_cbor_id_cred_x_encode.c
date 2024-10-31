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
#include "backend_cbor_id_cred_x_encode.h"
#include "zcbor_print.h"

#if DEFAULT_MAX_QTY != 3
#error "The type file was generated with a different default_max_qty than this file"
#endif

static bool encode_repeated_id_cred_x_kid(zcbor_state_t *state, const struct id_cred_x_kid_r *input);
static bool encode_COSE_X509(zcbor_state_t *state, const struct COSE_X509_r *input);
static bool encode_repeated_id_cred_x_x5chain(zcbor_state_t *state, const struct id_cred_x_x5chain *input);
static bool encode_COSE_CertHash(zcbor_state_t *state, const struct COSE_CertHash *input);
static bool encode_repeated_id_cred_x_x5t(zcbor_state_t *state, const struct id_cred_x_x5t *input);
static bool encode_id_cred_x(zcbor_state_t *state, const struct id_cred_x *input);


static bool encode_repeated_id_cred_x_kid(
		zcbor_state_t *state, const struct id_cred_x_kid_r *input)
{
	zcbor_log("%s\r\n", __func__);

	bool tmp_result = ((((zcbor_uint32_put(state, (4))))
	&& (((*input).id_cred_x_kid_choice == id_cred_x_kid_int_c) ? ((zcbor_int32_encode(state, (&(*input).id_cred_x_kid_int))))
	: (((*input).id_cred_x_kid_choice == id_cred_x_kid_bstr_c) ? ((zcbor_bstr_encode(state, (&(*input).id_cred_x_kid_bstr))))
	: false))));

	if (!tmp_result) {
		zcbor_trace_file(state);
		zcbor_log("%s error: %s\r\n", __func__, zcbor_error_str(zcbor_peek_error(state)));
	} else {
		zcbor_log("%s success\r\n", __func__);
	}

	return tmp_result;
}

static bool encode_COSE_X509(
		zcbor_state_t *state, const struct COSE_X509_r *input)
{
	zcbor_log("%s\r\n", __func__);

	bool tmp_result = (((((*input).COSE_X509_choice == COSE_X509_bstr_c) ? ((zcbor_bstr_encode(state, (&(*input).COSE_X509_bstr))))
	: (((*input).COSE_X509_choice == COSE_X509_certs_l_c) ? ((zcbor_list_start_encode(state, 3) && ((zcbor_multi_encode_minmax(2, 3, &(*input).COSE_X509_certs_l_certs_count, (zcbor_encoder_t *)zcbor_bstr_encode, state, (&(*input).COSE_X509_certs_l_certs), sizeof(struct zcbor_string))) || (zcbor_list_map_end_force_encode(state), false)) && zcbor_list_end_encode(state, 3)))
	: false))));

	if (!tmp_result) {
		zcbor_trace_file(state);
		zcbor_log("%s error: %s\r\n", __func__, zcbor_error_str(zcbor_peek_error(state)));
	} else {
		zcbor_log("%s success\r\n", __func__);
	}

	return tmp_result;
}

static bool encode_repeated_id_cred_x_x5chain(
		zcbor_state_t *state, const struct id_cred_x_x5chain *input)
{
	zcbor_log("%s\r\n", __func__);

	bool tmp_result = ((((zcbor_uint32_put(state, (33))))
	&& (encode_COSE_X509(state, (&(*input).id_cred_x_x5chain)))));

	if (!tmp_result) {
		zcbor_trace_file(state);
		zcbor_log("%s error: %s\r\n", __func__, zcbor_error_str(zcbor_peek_error(state)));
	} else {
		zcbor_log("%s success\r\n", __func__);
	}

	return tmp_result;
}

static bool encode_COSE_CertHash(
		zcbor_state_t *state, const struct COSE_CertHash *input)
{
	zcbor_log("%s\r\n", __func__);

	bool tmp_result = (((zcbor_list_start_encode(state, 2) && ((((((*input).COSE_CertHash_hashAlg_choice == COSE_CertHash_hashAlg_int_c) ? ((zcbor_int32_encode(state, (&(*input).COSE_CertHash_hashAlg_int))))
	: (((*input).COSE_CertHash_hashAlg_choice == COSE_CertHash_hashAlg_tstr_c) ? ((zcbor_tstr_encode(state, (&(*input).COSE_CertHash_hashAlg_tstr))))
	: false)))
	&& ((zcbor_bstr_encode(state, (&(*input).COSE_CertHash_hashValue))))) || (zcbor_list_map_end_force_encode(state), false)) && zcbor_list_end_encode(state, 2))));

	if (!tmp_result) {
		zcbor_trace_file(state);
		zcbor_log("%s error: %s\r\n", __func__, zcbor_error_str(zcbor_peek_error(state)));
	} else {
		zcbor_log("%s success\r\n", __func__);
	}

	return tmp_result;
}

static bool encode_repeated_id_cred_x_x5t(
		zcbor_state_t *state, const struct id_cred_x_x5t *input)
{
	zcbor_log("%s\r\n", __func__);

	bool tmp_result = ((((zcbor_uint32_put(state, (34))))
	&& (encode_COSE_CertHash(state, (&(*input).id_cred_x_x5t)))));

	if (!tmp_result) {
		zcbor_trace_file(state);
		zcbor_log("%s error: %s\r\n", __func__, zcbor_error_str(zcbor_peek_error(state)));
	} else {
		zcbor_log("%s success\r\n", __func__);
	}

	return tmp_result;
}

static bool encode_id_cred_x(
		zcbor_state_t *state, const struct id_cred_x *input)
{
	zcbor_log("%s\r\n", __func__);

	bool tmp_result = (((zcbor_map_start_encode(state, 3) && (((!(*input).id_cred_x_kid_present || encode_repeated_id_cred_x_kid(state, (&(*input).id_cred_x_kid)))
	&& (!(*input).id_cred_x_x5chain_present || encode_repeated_id_cred_x_x5chain(state, (&(*input).id_cred_x_x5chain)))
	&& (!(*input).id_cred_x_x5t_present || encode_repeated_id_cred_x_x5t(state, (&(*input).id_cred_x_x5t)))) || (zcbor_list_map_end_force_encode(state), false)) && zcbor_map_end_encode(state, 3))));

	if (!tmp_result) {
		zcbor_trace_file(state);
		zcbor_log("%s error: %s\r\n", __func__, zcbor_error_str(zcbor_peek_error(state)));
	} else {
		zcbor_log("%s success\r\n", __func__);
	}

	return tmp_result;
}



int cbor_encode_id_cred_x(
		uint8_t *payload, size_t payload_len,
		const struct id_cred_x *input,
		size_t *payload_len_out)
{
	zcbor_state_t states[5];

	return zcbor_entry_function(payload, payload_len, (void *)input, payload_len_out, states,
		(zcbor_decoder_t *)encode_id_cred_x, sizeof(states) / sizeof(zcbor_state_t), 1);
}
