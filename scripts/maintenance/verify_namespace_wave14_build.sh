#!/usr/bin/env bash
set -euo pipefail
cd /opt/projects/repositories/ioguard
rg -n "\brw_dpd\b|\brw_compress(_lzs|_lz4)?\b|\brw_firewall\b" CMakeLists.txt
