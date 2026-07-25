# =============================================================================
# tests/linux/robustness — fault-injection / resource-accounting tests.
#
# Unlike integration/ (functional handshake scenarios that assert protocol
# outputs), these probe the library's behaviour under adversarial conditions.
# Each concern lives in its own subdirectory, so new robustness suites (e.g.
# malformed messages or truncated buffers) slot in as siblings of oom_sweep/.
# =============================================================================

add_subdirectory(oom_sweep)
