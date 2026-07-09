Contributing
============

Contributions are welcome. This page mirrors the top-level
`CONTRIBUTING.md <https://github.com/kamil-kielbasa/libedhoc/blob/main/CONTRIBUTING.md>`_
file in the repository.

1. **Clone, fork, and branch.** Clone the repository with submodules, fork it
   on GitHub, add your fork as a remote, and create a topic branch:

   .. code-block:: bash

      git clone --recurse-submodules https://github.com/kamil-kielbasa/libedhoc.git
      cd libedhoc
      git remote add fork git@github.com:<you>/libedhoc.git
      git checkout -b feature/my-change

2. **Set up the workspace (Zephyr).** Initialise a shallow west workspace
   (the same flags CI uses):

   .. code-block:: bash

      west init -l libedhoc
      west update --narrow -o=--depth=1

3. **Build.** All builds go through ``scripts/ci.sh`` — the same entry point
   every CI job calls.

   Linux (GCC):

   .. code-block:: bash

      scripts/ci.sh build --gcc

   Linux (Clang):

   .. code-block:: bash

      scripts/ci.sh build --clang

   Zephyr:

   .. code-block:: bash

      west build -b native_sim libedhoc/sample/benchmark

4. **Code style.** Run the formatter through ``ci.sh``:

   .. code-block:: bash

      scripts/ci.sh format

5. **Test.** Run the test suite; fuzzers and sanitised builds (ASan / UBSan /
   Valgrind) are exercised by CI:

   .. code-block:: bash

      scripts/ci.sh test

6. **Documentation.** If you touch a public API or a header documented by
   Doxygen, rebuild the docs locally and confirm there are no warnings:

   .. code-block:: bash

      sphinx-build -W -b html doc doc/_build/html

7. **Pull request.** Open a PR against ``main`` with a clear description and
   make sure every CI workflow is green.

See :doc:`testing` for the full description of the test architecture and
:doc:`../guide/configuration` for build-time configuration options.
