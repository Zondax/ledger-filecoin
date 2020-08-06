# Fuzz testing the Ledger Filecoin app

The Filecoin app has several
[libFuzzer](http://llvm.org/docs/LibFuzzer.html) fuzzers for various
parts of the app.

## Building for fuzzing
Clang is required; this doesn't work with GCC at present.

To build for fuzzing, the `ENABLE_FUZZING` CMake option needs to be
used. This builds the Filecoin tests with fuzzing instrumentation.
You probably also want to combine this with the `ENABLE_SANITIZERS`
CMake option, to improve error-detecting capabilities:
```
$ cmake -B build \
        -DCMAKE_C_COMPILER=clang-10 \
        -DCMAKE_CXX_COMPILER=clang++-10 \
        -DCMAKE_BUILD_TYPE=Debug \
        -DENABLE_FUZZING=1 \
        -DENABLE_SANITIZERS=1 \
        .
$ make -C build
```

## Running fuzzers
There is a top-level Python 3 helper script, `run-fuzzers`, which
attempts to run each of the fuzz targets for a fixed amount of time with
existing input corpora, with reasonable settings for ASAN and UBSAN:

```
$ ./run-fuzzers
```

This script assumes that a fuzzer- and sanitizer-enabled build exists in
`build`.

Any crashes a fuzzer finds will be emitted to
`fuzz/corpora/FUZZ_TARGET-artifacts`.

## Reproducing a crash
You can reproduce a crash from a fuzz target by invoking it manually on
the crashing input. Often, the crash will be from one of the sanitizers
detecting an issue, so you will need to run with appropriate
`ASAN_OPTIONS` and `UBSAN_OPTIONS`.  For example:

```
$ ASAN_OPTIONS=halt_on_error=1 ./build/fuzz-base32_encode_decode fuzz/corpora/base32_encode_decode-artifacts/crash-be7854854df
c42b8171445a7c539f01a35b79dd6
INFO: Seed: 1322579982
INFO: Loaded 1 modules   (130 inline 8-bit counters): 130 [0x5ab5e0, 0x5ab662),
INFO: Loaded 1 PC tables (130 PCs): 130 [0x56e628,0x56ee48),
./build/fuzz-base32_encode_decode: Running 1 inputs 1 time(s) each.
Running: fuzz/corpora/base32_encode_decode-artifacts/crash-be7854854dfc42b8171445a7c539f01a35b79dd6
ledger-filecoin-private/app/src/base32.c:79:28: runtime error: left shift of 2004318071 by 8 places cannot be represented in type 'int'
SUMMARY: UndefinedBehaviorSanitizer: undefined-behavior ledger-filecoin-private/app/src/base32.c:79:28 in
ledger-filecoin-private/app/src/base32.c:33:16: runtime error: left shift of 501079517 by 5 places cannot be represented in type 'int'
SUMMARY: UndefinedBehaviorSanitizer: undefined-behavior ledger-filecoin-private/app/src/base32.c:33:16 in
=================================================================
==213100==ERROR: AddressSanitizer: global-buffer-overflow on address 0x000000f08100 at pc 0x00000055178e bp 0x7fff1b1d0e90 sp 0x7fff1b1d0e88
READ of size 1 at 0x000000f08100 thread T0
    #0 0x55178d in base32_decode ledger-filecoin-private/app/src/base32.c:28:59
    #1 0x551353 in LLVMFuzzerTestOneInput ledger-filecoin-private/fuzz/base32_encode_decode.cpp:27:24
    #2 0x459681 in fuzzer::Fuzzer::ExecuteCallback(unsigned char const*, unsigned long) (ledger-filecoin-private/build/fuzz-base32_encode_decode+0x459681)
    #3 0x444df2 in fuzzer::RunOneTest(fuzzer::Fuzzer*, char const*, unsigned long) (ledger-filecoin-private/build/fuzz-base32_encode_decode+0x444df2)
    #4 0x44a8a6 in fuzzer::FuzzerDriver(int*, char***, int (*)(unsigned char const*, unsigned long)) (ledger-filecoin-private/build/fuzz-base32_encode_decode+0x44a8a6)
    #5 0x473562 in main (ledger-filecoin-private/build/fuzz-base32_encode_decode+0x473562)
    #6 0x7f91463d80b2 in __libc_start_main /build/glibc-YYA7BZ/glibc-2.31/csu/../csu/libc-start.c:308:16
    #7 0x41f4bd in _start (ledger-filecoin-private/build/fuzz-base32_encode_decode+0x41f4bd)

0x000000f08100 is located 0 bytes to the right of global variable 'ENCODED' defined in 'ledger-filecoin-private/fuzz/base32_encode_decode.cpp:14:16' (0xf07d00) of size 1024
SUMMARY: AddressSanitizer: global-buffer-overflow ledger-filecoin-private/app/src/base32.c:28:59 in base32_decode
Shadow bytes around the buggy address:
  0x0000801d8fd0: 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00
  0x0000801d8fe0: 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00
  0x0000801d8ff0: 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00
  0x0000801d9000: 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00
  0x0000801d9010: 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00
=>0x0000801d9020:[f9]f9 f9 f9 f9 f9 f9 f9 f9 f9 f9 f9 f9 f9 f9 f9
  0x0000801d9030: f9 f9 f9 f9 f9 f9 f9 f9 f9 f9 f9 f9 f9 f9 f9 f9
  0x0000801d9040: 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00
  0x0000801d9050: 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00
  0x0000801d9060: 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00
  0x0000801d9070: 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00
Shadow byte legend (one shadow byte represents 8 application bytes):
  Addressable:           00
  Partially addressable: 01 02 03 04 05 06 07
  Heap left redzone:       fa
  Freed heap region:       fd
  Stack left redzone:      f1
  Stack mid redzone:       f2
  Stack right redzone:     f3
  Stack after return:      f5
  Stack use after scope:   f8
  Global redzone:          f9
  Global init order:       f6
  Poisoned by user:        f7
  Container overflow:      fc
  Array cookie:            ac
  Intra object redzone:    bb
  ASan internal:           fe
  Left alloca redzone:     ca
  Right alloca redzone:    cb
  Shadow gap:              cc
==213100==ABORTING
```
You can run this through a debugger, etc.

## Identifying fuzzer blind spots via source-based code coverage
To see if a fuzzer is getting stuck on certain parts of the code, you can
investigate source-based code coverage after running the fuzzer on all the
corpus inputs: source code that was not covered by that corpus was not
exercised by the fuzzer.

The CMake build has an `ENABLE_COVERAGE` option to build with [LLVM source
coverage](https://clang.llvm.org/docs/SourceBasedCodeCoverage.html), similar to
`gcov`.  Build the test code again, this time with the addition of coverage
support:
```
$ cmake -B build.coverage \
        -DCMAKE_C_COMPILER=clang-10 \
        -DCMAKE_CXX_COMPILER=clang++-10 \
        -DCMAKE_BUILD_TYPE=Debug \
        -DENABLE_COVERAGE=1 \
        -DENABLE_FUZZING=1 \
        .
$ make -C build.coverage
```

Then, run the fuzz target over every input in its corpus. For example:
```
$ find fuzz/corpora/base32_encode_decode -type f -print0 | xargs -0 ./build.coverage/fuzz-base32_encode_decode
```
This does not run the normal fuzz testing process, but instead runs that target
to reproduce behavior for each input in the corpus.

This produces a file `default.profraw`, which other LLVM tools can use to
produce a human-readable source-based code coverage report:
```
$ llvm-profdata-10 merge -sparse default.profraw -o default.profdata
$ llvm-cov-10 show ./build.coverage/fuzz-base32_encode_decode -instr-profile=default.profdata
```
