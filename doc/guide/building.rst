Building & testing
==================

Every build and test configuration lives in ``CMakePresets.json`` (plus
``tests/cmake/presets-linux.json``), so a CI step and a local reproduction are
the *same* command. The thin wrapper ``scripts/ci.sh`` bundles the common ones.

One preset, end to end
----------------------

.. code-block:: console

   $ scripts/ci.sh ci p256_stack
   # equivalent to:
   $ cmake --preset p256_stack
   $ cmake --build --preset p256_stack
   $ ctest --preset p256_stack

List every preset with ``scripts/ci.sh list`` (or ``cmake --list-presets``).
Preset names follow ``<suite-family>_<memory-backend>`` — e.g. ``p384_heap`` or
``mlkem512_custom``.

On macOS, use the Apple Clang preset. It configures liboqs for a portable CPU
target that works on both Arm64 and x86_64:

.. code-block:: console

   $ scripts/ci.sh ci macos

Whole matrix and instrumentation
--------------------------------

.. code-block:: console

   $ scripts/ci.sh matrix        # build + test every functional preset
   $ scripts/ci.sh coverage      # gcov + gcovr report
   $ scripts/ci.sh sanitizers    # ASan + UBSan
   $ scripts/ci.sh valgrind      # memcheck + DRD (all suites incl. PQC)
   $ scripts/ci.sh fuzz 60       # libFuzzer targets, 60 s each
   $ scripts/ci.sh format --check

Zephyr benchmark
----------------

The ZTEST benchmark under ``tests/zephyr`` runs the full handshake per cipher
suite and memory backend on ``native_sim``:

.. code-block:: console

   $ west twister -T tests/zephyr -p native_sim -W --inline-logs
