#!/usr/bin/env python3
from pathlib import Path

FILES = [
    Path('.claude/skills/storage-patterns/SKILL.md'),
    Path('docs/plans/2026-03-08-sprint-5-storage-security.md'),
    Path('docs/plans/2026-03-08-sprint-6-vertical-integration.md'),
    Path('src/core/secmod.c'),
    Path('src/core/secmod.h'),
    Path('src/storage/mdbx.c'),
    Path('src/storage/mdbx.h'),
    Path('src/storage/migrate.c'),
    Path('src/storage/migrate.h'),
    Path('src/storage/vault.c'),
    Path('src/storage/vault.h'),
    Path('src/auth/totp.h'),
    Path('tests/fuzz/fuzz_session_key.c'),
    Path('tests/integration/test_storage.c'),
    Path('tests/unit/test_storage_mdbx.c'),
    Path('tests/unit/test_storage_migrate.c'),
    Path('CMakeLists.txt'),
]

REPLACEMENTS = {
    'IOGUARD_STORAGE_MDBX_H': 'IOGUARD_STORAGE_MDBX_H',
    'IOGUARD_STORAGE_MIGRATE_H': 'IOGUARD_STORAGE_MIGRATE_H',
    'IOGUARD_AUTH_TOTP_H': 'IOGUARD_AUTH_TOTP_H',
    'IOG_MDBX_FORMAT_VERSION': 'IOG_MDBX_FORMAT_VERSION',
    'IOG_MDBX_MAX_READERS': 'IOG_MDBX_MAX_READERS',
    'IOG_MDBX_MAX_DBS': 'IOG_MDBX_MAX_DBS',
    'IOG_MDBX_SIZE_LOWER': 'IOG_MDBX_SIZE_LOWER',
    'IOG_MDBX_SIZE_UPPER': 'IOG_MDBX_SIZE_UPPER',
    'IOG_MDBX_GROWTH_STEP': 'IOG_MDBX_GROWTH_STEP',
    'IOG_MDBX_SHRINK_THRESHOLD': 'IOG_MDBX_SHRINK_THRESHOLD',
    'struct iog_vault': 'struct iog_vault',
    'typedef struct iog_vault': 'typedef struct iog_vault',
    'iog_mdbx_check_format': 'iog_mdbx_check_format',
    'iog_mdbx_close': 'iog_mdbx_close',
    'iog_mdbx_init': 'iog_mdbx_init',
    'iog_mdbx_ctx_t': 'iog_mdbx_ctx_t',
    'iog_migrate': 'iog_migrate',
    'iog_mdbx': 'iog_mdbx',
    'iog_vault': 'iog_vault',
    'iog_totp': 'iog_totp',
}

for path in FILES:
    text = path.read_text()
    original = text
    for old in sorted(REPLACEMENTS, key=len, reverse=True):
        text = text.replace(old, REPLACEMENTS[old])
    if text != original:
        path.write_text(text)
