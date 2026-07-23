# Contributing to libedhoc

Thanks for your interest in contributing! The steps below describe the
standard workflow.

## 1. Clone, fork, and branch

Clone the repository with submodules:

```bash
git clone --recurse-submodules https://github.com/kamil-kielbasa/libedhoc.git
cd libedhoc
```

Fork the repository on GitHub, add your fork as a remote, and create a topic
branch:

```bash
git remote add fork git@github.com:<you>/libedhoc.git
git checkout -b feature/my-change
```

## 2. Set up the workspace (Zephyr)

For Zephyr-based development, initialise a shallow west workspace (same
flags CI uses):

```bash
west init -l libedhoc
west update --narrow -o=--depth=1
```

## 3. Build

All builds go through the unified `scripts/ci.sh` entry point — the same
script every CI job calls.

**Linux (GCC):**

```bash
scripts/ci.sh build --gcc
```

**Linux (Clang):**

```bash
scripts/ci.sh build --clang
```

**Zephyr (west):**

```bash
west build -b native_sim libedhoc/sample/benchmark
```

## 4. Code style

Run the formatter (clang-format under the hood) through `ci.sh`:

```bash
scripts/ci.sh format
```

## 5. Test

Run the test suite and check coverage; fuzzers and sanitised builds (ASan /
UBSan / Valgrind) are exercised by CI:

```bash
scripts/ci.sh test
```

## 6. Documentation

If you touch a public API or a header documented by Doxygen, rebuild the
docs locally and confirm there are no warnings:

```bash
pip install -r doc/requirements.txt
sphinx-build -W -b html doc doc/_build/html
```

The docs need Doxygen ≥ 1.17.0; older versions mis-parse the anonymous unions
in `credentials.h` and fail the `-W` build.

## 7. Changelog

Every PR must add an entry to `CHANGELOG.rst` under a new (or the current
unreleased) version section, briefly summarising the user-visible change.
PRs without a changelog update will be rejected during review.

## 8. Pull request

Open a PR against `main` with a clear description and make sure every CI
workflow is green.
