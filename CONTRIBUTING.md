# Contributing to libedhoc

## Getting the sources

```bash
git clone --recurse-submodules https://github.com/kamil-kielbasa/libedhoc.git
```

For Zephyr work, initialise a west workspace on top of the checkout:

```bash
west init -l libedhoc
west update --narrow -o=--depth=1
```

## Building, testing, checking

Everything goes through `scripts/ci.sh`, the same entry point every CI job
calls. Run it without arguments for the command list:

```bash
scripts/ci.sh help          # commands
scripts/ci.sh list          # build presets
```

The usual loop is one preset end to end, then the functional matrix:

```bash
scripts/ci.sh ci legacy     # configure, build and test one preset
scripts/ci.sh matrix        # every cipher suite, method and memory backend
```

The remaining commands — `format`, `coverage`, `sanitizers`, `valgrind`,
`fuzz`, `cppcheck`, `clang-tidy`, `check-headers`, `check-matrix` — mirror the
jobs in [`.github/workflows/`](.github/workflows/). Read those workflows to see
what actually runs on a pull request; they are the specification, this file is
not.

Zephyr is the one thing `ci.sh` does not cover. It is built and run by twister,
from the west workspace root:

```bash
ZEPHYR_TOOLCHAIN_VARIANT=host ./zephyr/scripts/twister \
    --testsuite-root libedhoc/tests/zephyr --platform native_sim \
    --outdir twister-out --disable-warnings-as-errors
```

## Documentation

Touching a public header or anything under `doc/` means rebuilding the docs
warning-free:

```bash
pip install -r doc/requirements.txt
sphinx-build -W -b html doc doc/_build/html
```

Doxygen must be >= 1.17.0; older versions mis-parse the anonymous unions in
`include/edhoc/credentials.h` and fail the `-W` build.

## Pull requests

* Branch off `main`, open the PR against `main`, and keep every CI workflow
  green.
* Add an entry to `CHANGELOG.rst` describing the user-visible change. A PR
  without one is not reviewed.
* Run `scripts/ci.sh format` before pushing; CI rejects unformatted code.
