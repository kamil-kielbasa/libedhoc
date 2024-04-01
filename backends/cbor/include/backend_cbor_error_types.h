/*
 * Generated using zcbor version 0.7.0
 * https://github.com/NordicSemiconductor/zcbor
 * Generated with a --default-max-qty of 3
 */

#ifndef BACKEND_CBOR_ERROR_TYPES_H__
#define BACKEND_CBOR_ERROR_TYPES_H__

#include <stdint.h>
#include <stdbool.h>
#include <stddef.h>


#ifdef __cplusplus
extern "C" {
#endif

/** Which value for --default-max-qty this file was created with.
 *
 *  The define is used in the other generated file to do a build-time
 *  compatibility check.
 *
 *  See `zcbor --help` for more information about --default-max-qty
 */
#define DEFAULT_MAX_QTY 3

struct error {
	int32_t _error_ERR_CODE;
};

#ifdef __cplusplus
}
#endif

#endif /* BACKEND_CBOR_ERROR_TYPES_H__ */
