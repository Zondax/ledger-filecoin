#!/usr/bin/env python3

import os
import random
import shlex
import subprocess
import time
import sys

MAX_SECONDS_PER_RUN = 600
CRASH_TIMEOUT = 30
MUTATE_DEPTH = random.randint(1, 20)

# Create logs directory for crash analysis
logs_dir = os.path.abspath(os.path.join('fuzz', 'logs'))
os.makedirs(logs_dir, exist_ok=True)

# (fuzzer name, max length, max time scale factor)
CONFIGS = [
    ('parser_parse', 17000, 4),
]

def analyze_crash(fuzzer, crash_file, fuzz_path):
    """Analyze a single crash file with detailed logging"""
    print(f"\n🔍 Analyzing crash: {crash_file}")
    
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
        'mmap_limit_mb=512:'
        'fast_unwind_on_malloc=0'
    )
    
    env['UBSAN_OPTIONS'] = (
        'halt_on_error=1:'
        'print_stacktrace=1:'
        'symbolize=1:'
        'print_summary=1:'
        'silence_unsigned_overflow=0'
    )
    
    # Prepare logging
    log_file = os.path.join(logs_dir, f'crash_{fuzzer}_{os.path.basename(crash_file)}.log')
    
    cmd = [fuzz_path, crash_file]
    print(f"Command: {' '.join(shlex.quote(c) for c in cmd)}")
    
    try:
        # Run with timeout and capture output
        with open(log_file, 'w') as log:
            log.write(f"Crash analysis for: {crash_file}\n")
            log.write(f"Command: {' '.join(cmd)}\n")
            log.write(f"Timestamp: {time.strftime('%Y-%m-%d %H:%M:%S')}\n")
            log.write("=" * 50 + "\n\n")
            log.flush()
            
            result = subprocess.run(
                cmd, 
                env=env, 
                timeout=CRASH_TIMEOUT,
                capture_output=True,
                text=True
            )
            
            log.write("STDOUT:\n")
            log.write(result.stdout)
            log.write("\nSTDERR:\n")
            log.write(result.stderr)
            log.write(f"\nReturn code: {result.returncode}\n")
        
        if result.returncode != 0:
            print(f"❌ Crash reproduced! Return code: {result.returncode}")
            print(f"📝 Details saved to: {log_file}")
            return result.returncode
        else:
            print(f"✅ No crash (return code: 0)")
            return 0
            
    except subprocess.TimeoutExpired:
        print(f"⏰ Timeout after {CRASH_TIMEOUT}s - possible infinite loop")
        with open(log_file, 'a') as log:
            log.write(f"\nTIMEOUT after {CRASH_TIMEOUT} seconds\n")
        return -1
    except Exception as e:
        print(f"💥 Error running crash: {e}")
        return -1

for config in CONFIGS:
    fuzzer, max_len, scale_factor = config
    print(f'\n######## Analyzing crashes for {fuzzer} ########')

    artifact_dir = os.path.join('fuzz', 'corpora', f'{fuzzer}-artifacts')
    corpus_dir = os.path.join('fuzz', 'corpora', f'{fuzzer}')
    fuzz_path = os.path.abspath(os.path.join(f'build/fuzz-{fuzzer}'))

    if not os.path.exists(artifact_dir):
        print(f"No artifact directory found: {artifact_dir}")
        continue
        
    if not os.path.exists(fuzz_path):
        print(f"Fuzzer binary not found: {fuzz_path}")
        continue

    crash_files = [f for f in os.listdir(artifact_dir) if os.path.isfile(os.path.join(artifact_dir, f))]
    
    if not crash_files:
        print(f"✅ No crash files found in {artifact_dir}")
        continue
    
    print(f"Found {len(crash_files)} crash files")
    
    crashes_reproduced = 0
    for crash_file in crash_files:
        crash_path = os.path.join(artifact_dir, crash_file)
        error_code = analyze_crash(fuzzer, crash_path, fuzz_path)
        
        if error_code != 0:
            crashes_reproduced += 1
    
    print(f"\n📊 Summary for {fuzzer}:")
    print(f"Total crash files: {len(crash_files)}")
    print(f"Crashes reproduced: {crashes_reproduced}")
    print(f"Logs saved to: {logs_dir}")
    
    if crashes_reproduced > 0:
        print(f"\n🚨 {crashes_reproduced} crashes need attention!")
        sys.exit(1)

print("\n✅ All crash analysis completed successfully!")


