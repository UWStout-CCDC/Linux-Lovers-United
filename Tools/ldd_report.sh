#!/usr/bin/env bash
# Usage: ./ldd_report.sh <command>

set -euo pipefail

if [[ $# -lt 1 ]]; then
    echo "Usage: $0 <command>" >&2
    exit 1
fi

CMD="$1"

# Resolve full path using which
if ! CMD_PATH=$(which "$CMD" 2>/dev/null); then
    echo "Error: '$CMD' not found in PATH." >&2
    exit 1
fi

echo "Shared library report for: $CMD_PATH"
echo "=================================================="

# Run ldd and capture output
LDD_OUTPUT=$(ldd "$CMD_PATH" 2>&1)
if [[ $? -ne 0 ]]; then
    echo "Error running ldd on '$CMD_PATH':" >&2
    echo "$LDD_OUTPUT" >&2
    exit 1
fi

# Parse paths from ldd output.
# ldd lines look like:
#   libfoo.so.1 => /lib/x86_64-linux-gnu/libfoo.so.1 (0x00007f...)
#   /lib64/ld-linux-x86-64.so.2 (0x00007f...)
#   linux-vdso.so.1 => (0x00007f...)   [no path, virtual]
PATHS=$(echo "$LDD_OUTPUT" | awk '
    /=>/ {
        # lines with "=>": path is the field after "=>"
        if ($3 != "" && $3 != "(0x" && $3 !~ /^\(/) print $3
    }
    !/=>/ {
        # lines without "=>": first field is the path if it starts with "/"
        if ($1 ~ /^\//) print $1
    }
')

if [[ -z "$PATHS" ]]; then
    echo "No shared library paths found."
    exit 0
fi

printf "%-55s  %s\n" "Library" "Last Modified"
printf "%-55s  %s\n" "-------" "-------------"

while IFS= read -r lib; do
    if [[ -f "$lib" ]]; then
        mtime=$(stat --format="%y" "$lib" 2>/dev/null | cut -d'.' -f1)
        printf "%-55s  %s\n" "$lib" "$mtime"
    else
        printf "%-55s  %s\n" "$lib" "[not found]"
    fi
done <<< "$PATHS"
