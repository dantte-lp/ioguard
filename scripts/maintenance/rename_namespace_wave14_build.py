#!/usr/bin/env python3
from pathlib import Path

path = Path('CMakeLists.txt')
text = path.read_text()
replacements = {
    'iog_compress_lzs': 'iog_compress_lzs',
    'iog_compress_lz4': 'iog_compress_lz4',
    'iog_compress': 'iog_compress',
    'iog_firewall': 'iog_firewall',
    'iog_dpd': 'iog_dpd',
}
for old in sorted(replacements, key=len, reverse=True):
    text = text.replace(old, replacements[old])
path.write_text(text)
