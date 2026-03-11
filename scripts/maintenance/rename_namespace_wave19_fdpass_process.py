#!/usr/bin/env python3
from pathlib import Path

FILES = [
    Path('src/ipc/fdpass.h'),
    Path('src/ipc/fdpass.c'),
    Path('src/core/process.h'),
    Path('src/core/process.c'),
    Path('src/core/main.h'),
    Path('src/core/main.c'),
    Path('tests/unit/test_fdpass.c'),
    Path('tests/unit/test_process.c'),
    Path('tests/unit/test_main_bootstrap.c'),
    Path('tests/unit/test_worker_loop.c'),
    Path('src/core/worker_loop.c'),
    Path('CMakeLists.txt'),
]

REPLACEMENTS = {
    'IOGUARD_IPC_FDPASS_H': 'IOGUARD_IPC_FDPASS_H',
    'IOGUARD_CORE_PROCESS_H': 'IOGUARD_CORE_PROCESS_H',
    'IOGUARD_CORE_MAIN_H': 'IOGUARD_CORE_MAIN_H',
    'IOG_FDPASS_MAX_FDS': 'IOG_FDPASS_MAX_FDS',
    'iog_fdpass_send': 'iog_fdpass_send',
    'iog_fdpass_recv': 'iog_fdpass_recv',
    'iog_process_spawn': 'iog_process_spawn',
    'iog_process_wait': 'iog_process_wait',
    'iog_process_signal': 'iog_process_signal',
    'iog_process_cleanup': 'iog_process_cleanup',
    'iog_process_t': 'iog_process_t',
    'iog_main_parse_args': 'iog_main_parse_args',
    'iog_main_create_ipc_pair': 'iog_main_create_ipc_pair',
    'iog_main_create_accept_pair': 'iog_main_create_accept_pair',
    'iog_main_create_signalfd': 'iog_main_create_signalfd',
    'iog_fdpass': 'iog_fdpass',
    'iog_core': 'iog_core',
}

for path in FILES:
    text = path.read_text()
    original = text
    for old in sorted(REPLACEMENTS, key=len, reverse=True):
        text = text.replace(old, REPLACEMENTS[old])
    if text != original:
        path.write_text(text)
