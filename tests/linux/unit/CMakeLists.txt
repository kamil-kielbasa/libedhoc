# =============================================================================
# tests/linux/unit — the library's suite-independent logic in one binary.
#
# Covers the public API, message paths, internals, exporters and CoAP helpers.
# None of it depends on the cipher suite, so the binary is pinned to suite 2.
# =============================================================================

if(NOT CONFIG_LIBEDHOC_CIPHER_SUITE_2_ENABLE)
    return()
endif()

# These asserts are allocator-agnostic, and the custom backend is already
# covered by robustness/oom_sweep and rfc9529.
if(CONFIG_LIBEDHOC_MEM_BACKEND EQUAL 2)
    return()
endif()

set(_unit_sources
    api/test_api.c
    api/test_api_negative.c
    coap/test_coap.c
    error/test_error_message.c
    exporters/test_exporters.c
    message/test_message_paths.c
    coverage/support/coverage_common.c
    coverage/test_coverage_msg1.c
    coverage/test_coverage_msg2.c
    coverage/test_coverage_msg3.c
    coverage/test_coverage_msg4.c
    coverage/test_coverage_exporters.c
    coverage/test_coverage_error.c
    coverage/test_coverage_cbor.c
    coverage/test_coverage_handshake.c
    coverage/test_coverage_sweep_validate.c
    internals/support/internals_common.c
    internals/test_internals_common.c
    internals/test_internals_credentials.c
    internals/test_internals_ead.c
    internals/test_internals_mac.c
    internals/test_internals_message1.c
    internals/test_internals_message2.c
    internals/test_internals_message3.c
    internals/test_internals_message4.c)

# Kept in execution order; the runner is generated from this list.
set(_unit_groups
    api api_negative error_message exporters coap
    coverage_msg1 coverage_msg2 coverage_msg3 coverage_msg4
    coverage_exporters coverage_error coverage_cbor coverage_handshake
    coverage_sweep_validate
    internals_common internals_mac internals_message1 internals_message2
    internals_message3 internals_message4
    internals_credentials internals_ead
    message_paths)

edhoc_add_unity_test(
    NAME          test_unit
    SOURCES       ${_unit_sources}
    GROUPS        ${_unit_groups}
    SUITE_SOURCES ${LIBEDHOC_CIPHER_SUITE_SOURCES}
    INCLUDE       ${CMAKE_CURRENT_SOURCE_DIR}/coverage/support
                  ${CMAKE_CURRENT_SOURCE_DIR}/internals/support)
