#!/usr/bin/env python3
from pathlib import Path

FILES = [
    Path('.claude/skills/c23-standards/SKILL.md'),
    Path('.claude/skills/coding-standards/SKILL.md'),
    Path('.claude/skills/security-coding/SKILL.md'),
    Path('.claude/skills/storage-patterns/SKILL.md'),
    Path('CMakeLists.txt'),
    Path('docs/plans/2026-03-07-sprint-1-foundation.md'),
    Path('docs/plans/2026-03-07-sprint-2-tls-auth.md'),
    Path('docs/plans/2026-03-08-ioguard-rebranding-plan.md'),
    Path('docs/plans/2026-03-08-sprint-5-storage-security.md'),
    Path('docs/plans/2026-03-08-sprint-6-vertical-integration.md'),
    Path('docs/plans/2026-03-10-sprint-7-auth-observability.md'),
    Path('src/config/config.h'),
    Path('src/core/session.h'),
    Path('src/crypto/session_cache.h'),
]

REPLACEMENTS = {
    'IOGUARD_CONFIG_CONFIG_H': 'IOGUARD_CONFIG_CONFIG_H',
    'IOGUARD_CORE_SESSION_H': 'IOGUARD_CORE_SESSION_H',
    'IOGUARD_SESSION_CACHE_H': 'IOGUARD_SESSION_CACHE_H',
    'iog_main_helpers': 'iog_main_helpers',
    'iog_memory': 'iog_memory',
    'iog_config': 'iog_config',
    'iog_session': 'iog_session',
}

for path in FILES:
    text = path.read_text()
    original = text
    for old in sorted(REPLACEMENTS, key=len, reverse=True):
        text = text.replace(old, REPLACEMENTS[old])
    if text != original:
        path.write_text(text)
