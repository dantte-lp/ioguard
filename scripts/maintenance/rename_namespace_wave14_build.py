#!/usr/bin/env python3
from pathlib import Path

path = Path('CMakeLists.txt')
text = path.read_text()
replacements = {
    'rw_compress_lzs': 'iog_compress_lzs',
    'rw_compress_lz4': 'iog_compress_lz4',
    'rw_compress': 'iog_compress',
    'rw_firewall': 'iog_firewall',
    'rw_dpd': 'iog_dpd',
}
for old in sorted(replacements, key=len, reverse=True):
    text = text.replace(old, replacements[old])
path.write_text(text)
