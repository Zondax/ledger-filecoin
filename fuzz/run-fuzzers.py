#!/usr/bin/env python3

import os
import random
import shlex
import subprocess

MAX_SECONDS_PER_RUN = 600
MUTATE_DEPTH = random.randint(1, 20)

# Create coverage directory specifically in fuzz/coverage
coverage_dir = os.path.abspath(os.path.join('fuzz', 'coverage'))
os.makedirs(coverage_dir, exist_ok=True)

# Create logs directory specifically in fuzz/logs
logs_dir = os.path.abspath(os.path.join('fuzz', 'logs'))
os.makedirs(logs_dir, exist_ok=True)

# (fuzzer name, max length, max time scale factor)
CONFIGS = [
    ('parser_parse', 17000, 4),
]

for config in CONFIGS:
    fuzzer, max_len, scale_factor = config
    max_time = MAX_SECONDS_PER_RUN * scale_factor
    print(f'######## {fuzzer} ########')

    artifact_dir = os.path.join('fuzz', 'corpora', f'{fuzzer}-artifacts')
    corpus_dir = os.path.join('fuzz', 'corpora', f'{fuzzer}')
    fuzz_path = os.path.abspath(os.path.join(f'build/fuzz-{fuzzer}'))

    os.makedirs(artifact_dir, exist_ok=True)
    os.makedirs(corpus_dir, exist_ok=True)

    env = os.environ.copy()
    env['ASAN_OPTIONS'] = (
        'halt_on_error=1:'
        'print_stacktrace=1:'
        'detect_stack_use_after_return=true:'
        'detect_stack_use_after_scope=true:'
        'symbolize=1:'
        'print_module_map=2:'
        'handle_segv=1:'
        'handle_sigbus=1:'
        'handle_abort=1:'
        'handle_sigfpe=1:'
        'allow_user_segv_handler=0:'
        'use_sigaltstack=1:'
        'detect_odr_violation=1:'
        'fast_unwind_on_malloc=0'
    )
    
    env['UBSAN_OPTIONS'] = (
        'halt_on_error=1:'
        'print_stacktrace=1:'
        'symbolize=1:'
        'print_summary=1:'
        'silence_unsigned_overflow=0'
    )
    
    # Configure libFuzzer to output coverage files to fuzz/coverga directory
    env['LLVM_PROFILE_FILE'] = f'{coverage_dir}/%p.profraw'

    # Convert relative paths to absolute paths since we're changing working directory
    artifact_dir = os.path.abspath(artifact_dir)
    corpus_dir = os.path.abspath(corpus_dir)
    
    cmd = [fuzz_path, f'-max_total_time={max_time}',
           f'-timeout=20',
           f'-rss_limit_mb=2048',
           f'-jobs=16',
           f'-max_len={max_len}',
           f'-mutate_depth={MUTATE_DEPTH}',
           f'-artifact_prefix={artifact_dir}/',
           corpus_dir]
    print(' '.join(shlex.quote(c) for c in cmd))

    original_cwd = os.getcwd()
    try:
        os.chdir(logs_dir)
        subprocess.call(cmd, env=env)
    finally:
        os.chdir(original_cwd)
