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
    'RINGWALL_IPC_FDPASS_H': 'IOGUARD_IPC_FDPASS_H',
    'RINGWALL_CORE_PROCESS_H': 'IOGUARD_CORE_PROCESS_H',
    'RINGWALL_CORE_MAIN_H': 'IOGUARD_CORE_MAIN_H',
    'RW_FDPASS_MAX_FDS': 'IOG_FDPASS_MAX_FDS',
    'rw_fdpass_send': 'iog_fdpass_send',
    'rw_fdpass_recv': 'iog_fdpass_recv',
    'rw_process_spawn': 'iog_process_spawn',
    'rw_process_wait': 'iog_process_wait',
    'rw_process_signal': 'iog_process_signal',
    'rw_process_cleanup': 'iog_process_cleanup',
    'rw_process_t': 'iog_process_t',
    'rw_main_parse_args': 'iog_main_parse_args',
    'rw_main_create_ipc_pair': 'iog_main_create_ipc_pair',
    'rw_main_create_accept_pair': 'iog_main_create_accept_pair',
    'rw_main_create_signalfd': 'iog_main_create_signalfd',
    'rw_fdpass': 'iog_fdpass',
    'rw_core': 'iog_core',
}

for path in FILES:
    text = path.read_text()
    original = text
    for old in sorted(REPLACEMENTS, key=len, reverse=True):
        text = text.replace(old, REPLACEMENTS[old])
    if text != original:
        path.write_text(text)
