#!/usr/bin/env python3
from __future__ import annotations

import subprocess
from pathlib import Path

ROOT = Path('/opt/projects/repositories/ioguard')

TEXT_REPLACEMENTS = [
    ('rwctl', 'iogctl'),
    ('ioguard.toml', 'ioguard.toml'),
    ('/etc/ioguard/', '/etc/ioguard/'),
    ('/var/lib/ioguard/', '/var/lib/ioguard/'),
    ('localhost/ioguard-dev', 'localhost/ioguard-dev'),
    ('localhost/ioguard-test', 'localhost/ioguard-test'),
    ('localhost/ioguard-build', 'localhost/ioguard-build'),
    ('localhost/ioguard-ci', 'localhost/ioguard-ci'),
    ('ghcr.io/dantte-lp/ioguard-dev', 'ghcr.io/dantte-lp/ioguard-dev'),
    ('ghcr.io/dantte-lp/ioguard-test', 'ghcr.io/dantte-lp/ioguard-test'),
    ('ghcr.io/dantte-lp/ioguard-build', 'ghcr.io/dantte-lp/ioguard-build'),
    ('ghcr.io/dantte-lp/ioguard-ci', 'ghcr.io/dantte-lp/ioguard-ci'),
    ('io.ioguard.', 'io.ioguard.'),
    ('org.opencontainers.image.title=ioguard-dev', 'org.opencontainers.image.title=ioguard-dev'),
    ('org.opencontainers.image.title=ioguard-test', 'org.opencontainers.image.title=ioguard-test'),
    ('org.opencontainers.image.title=ioguard-build', 'org.opencontainers.image.title=ioguard-build'),
    ('org.opencontainers.image.title=ioguard-ci', 'org.opencontainers.image.title=ioguard-ci'),
    ('ioguard-dev', 'ioguard-dev'),
    ('ioguard-test', 'ioguard-test'),
    ('ioguard-build', 'ioguard-build'),
    ('ioguard-ci', 'ioguard-ci'),
    ('ioguard-connect', 'ioguard-connect'),
    ('ioguard-docs', 'ioguard-docs'),
]

EXCLUDED_SUFFIXES = {
    'docs/plans/2026-03-11-ioguard-legacy-name-inventory.md',
    'docs/plans/2026-03-11-ioguard-naming-options.md',
}

EXCLUDED_PREFIXES = (
    'docs/tmp/',
    'scripts/maintenance/',
)

TARGET_EXTENSIONS = {
    '.md', '.c', '.h', '.sh', '.yaml', '.yml', '.toml', '.txt', '.in', '.cmake', '.service', '.socket',
}

TARGET_FILENAMES = {
    'README', 'README.md', 'Makefile', 'Containerfile', 'Containerfile.dev', 'Containerfile.test', 'Containerfile.ci'
}


def tracked_files() -> list[Path]:
    proc = subprocess.run(
        ['git', '-C', str(ROOT), 'ls-files'],
        check=True,
        capture_output=True,
        text=True,
    )
    paths = []
    for line in proc.stdout.splitlines():
        rel = line.strip()
        if not rel:
            continue
        if rel in EXCLUDED_SUFFIXES:
            continue
        if any(rel.startswith(prefix) for prefix in EXCLUDED_PREFIXES):
            continue
        path = ROOT / rel
        if not path.is_file():
            continue
        if path.suffix in TARGET_EXTENSIONS or path.name in TARGET_FILENAMES:
            paths.append(path)
    return paths


def rewrite_file(path: Path) -> bool:
    try:
        original = path.read_text(encoding='utf-8')
    except UnicodeDecodeError:
        return False

    updated = original
    for old, new in TEXT_REPLACEMENTS:
        updated = updated.replace(old, new)

    if updated == original:
        return False

    path.write_text(updated, encoding='utf-8')
    return True


def main() -> int:
    changed = 0
    for path in tracked_files():
        if rewrite_file(path):
            print(path.relative_to(ROOT))
            changed += 1

    old_fixture = ROOT / 'tests/fixtures/ioguard.toml'
    new_fixture = ROOT / 'tests/fixtures/ioguard.toml'
    if old_fixture.exists() and not new_fixture.exists():
        subprocess.run(
            ['git', '-C', str(ROOT), 'mv', str(old_fixture), str(new_fixture)],
            check=True,
        )
        print('tests/fixtures/ioguard.toml -> tests/fixtures/ioguard.toml')
        changed += 1

    print(f'changed={changed}')
    return 0


if __name__ == '__main__':
    raise SystemExit(main())
