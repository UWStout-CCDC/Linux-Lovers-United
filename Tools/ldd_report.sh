#!/usr/bin/env bash
# ldd_report.sh - Shared library report with selectable timestamps
# Usage: ./ldd_report.sh [-m] [-c] [-a] <command>

set -euo pipefail

USE_MTIME=false
USE_CTIME=false
USE_ATIME=false

usage() {
    echo "Usage: $0 [-m] [-c] [-a] <command>"
    echo ""
    echo "Flags (at least one required):"
    echo "  -m   Show mtime  (last content modification)"
    echo "  -c   Show ctime  (last metadata/content change — cannot be forged)"
    echo "  -a   Show atime  (last access/read)"
    echo ""
    echo "Examples:"
    echo "  $0 -m  sshd      # mtime only"
    echo "  $0 -mc bash      # mtime + ctime"
    echo "  $0 -mca nginx    # all three"
    exit 1
}

while getopts ":mca" opt; do
    case "$opt" in
        m) USE_MTIME=true ;;
        c) USE_CTIME=true ;;
        a) USE_ATIME=true ;;
        *) echo "Error: Unknown flag -${OPTARG}" >&2; usage ;;
    esac
done
shift $(( OPTIND - 1 ))

if ! $USE_MTIME && ! $USE_CTIME && ! $USE_ATIME; then
    echo "Error: At least one timestamp flag (-m, -c, -a) is required." >&2
    usage
fi

if [[ $# -lt 1 ]]; then
    echo "Error: No command specified." >&2
    usage
fi

CMD="$1"

if ! CMD_PATH=$(which "$CMD" 2>/dev/null); then
    echo "Error: '$CMD' not found in PATH." >&2
    exit 1
fi

# Build timestamp label string for header
LABELS=()
$USE_MTIME && LABELS+=( "mtime" )
$USE_CTIME && LABELS+=( "ctime" )
$USE_ATIME && LABELS+=( "atime" )
LABEL_STR=$(IFS="|"; echo "${LABELS[*]}")

echo "Shared library report for: $CMD_PATH  [${LABEL_STR}]"
echo "========================================================================"

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
        if ($3 != "" && $3 != "(0x" && $3 !~ /^\(/) print $3
    }
    !/=>/ {
        if ($1 ~ /^\//) print $1
    }
')

if [[ -z "$PATHS" ]]; then
    echo "No shared library paths found."
    exit 0
fi

printf "%-55s  %s\n" "Library" "Timestamp(s)"
printf "%-55s  %s\n" "-------" "------------"

get_timestamps() {
    local file="$1"
    local out=()
    $USE_MTIME && out+=( "mtime: $(stat --format='%y' "$file" 2>/dev/null | cut -d'.' -f1)" )
    $USE_CTIME && out+=( "ctime: $(stat --format='%z' "$file" 2>/dev/null | cut -d'.' -f1)" )
    $USE_ATIME && out+=( "atime: $(stat --format='%x' "$file" 2>/dev/null | cut -d'.' -f1)" )
    (IFS=" | "; echo "${out[*]}")
}

while IFS= read -r lib; do
    if [[ -f "$lib" ]]; then
        timestamps=$(get_timestamps "$lib")
        printf "%-55s  %s\n" "$lib" "$timestamps"
    else
        printf "%-55s  %s\n" "$lib" "[not found]"
    fi
done <<< "$PATHS"
