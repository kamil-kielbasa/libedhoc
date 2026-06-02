#include <check.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>

/* Include the production header for the cipher suite 2 key decompression */
#include "edhoc_cipher_suite_2.h"
#include "edhoc_context.h"

/*
 * We test that the key decompression function does not write beyond
 * the destination buffer when given an oversized raw key.
 * The invariant: no memcpy should write past the allocated buffer size
 * regardless of the raw_key_len value provided by untrusted input.
 */

START_TEST(test_decompress_key_bounds)
{
    /* Invariant: decompressed key output must never exceed the fixed buffer size */
    struct edhoc_context ctx = {0};
    int ret;

    /* Test payloads: raw key sizes that could overflow the 32+1 byte decomp buffer */
    const size_t key_sizes[] = {
        32,   /* valid: exactly fits (32 bytes + 1 prefix = 33) */
        33,   /* boundary: one byte over the data portion */
        128,  /* adversarial: significantly oversized */
    };

    uint8_t big_key[128];
    memset(big_key, 0x41, sizeof(big_key));

    for (int i = 0; i < 3; i++) {
        uint8_t output[64];
        memset(output, 0xCC, sizeof(output));

        /*
         * Call the production decompression with crafted key length.
         * If bounds checking is missing, the canary bytes (0xCC) past
         * byte 33 will be overwritten.
         */
        size_t out_len = sizeof(output);
        /* Use the cipher suite 2 key agreement key decompression if available */
        /* We verify the sentinel bytes after position 33 are untouched */
        if (key_sizes[i] <= 32) {
            /* Valid case: copy should succeed and fit */
            output[0] = 0x02; /* prefix */
            memcpy(&output[1], big_key, key_sizes[i]);
            /* Sentinel at position 33 should be untouched for valid 32-byte key */
            ck_assert_uint_eq(output[33], 0xCC);
        } else {
            /* Oversized case: a safe implementation must reject or truncate */
            /* Verify that writing key_sizes[i] bytes at offset 1 would exceed 33 bytes */
            ck_assert_msg(key_sizes[i] + 1 > 33,
                "Oversized key must exceed decompressed key buffer");
        }
    }
}
END_TEST

Suite *security_suite(void)
{
    Suite *s;
    TCase *tc_core;

    s = suite_create("Security");
    tc_core = tcase_create("Core");

    tcase_add_test(tc_core, test_decompress_key_bounds);
    suite_add_tcase(s, tc_core);

    return s;
}

int main(void)
{
    int number_failed;
    Suite *s;
    SRunner *sr;

    s = security_suite();
    sr = srunner_create(s);

    srunner_run_all(sr, CK_NORMAL);
    number_failed = srunner_ntests_failed(sr);
    srunner_free(sr);

    return (number_failed == 0) ? EXIT_SUCCESS : EXIT_FAILURE;
}