#!/bin/bash
# large_finder.sh - Find files exceeding a size threshold
# Usage: ./large_finder.sh [options] <directory>
#
# Options:
#   -s <size>   Size threshold (default: 100M)
#               Accepts find(1) size suffixes: c (bytes), k (KB), M (MB), G (GB)
#   -o <file>   Output file path (default: /tmp/large_files_<timestamp>.txt)
#   -h          Show this help message
#
# Examples:
#   ./large_finder.sh /home
#   ./large_finder.sh -s 500M /var
#   ./large_finder.sh -s 1G -o /tmp/results.txt /

set -euo pipefail

DEFAULT_SIZE="100M"
SIZE_THRESHOLD="$DEFAULT_SIZE"
OUTPUT="/tmp/large_files_$(date +%Y%m%d_%H%M%S).txt"

usage() {
    grep "^#" "$0" | grep -v "^#!/" | sed 's/^# \{0,1\}//'
    exit 0
}

while getopts "s:o:h" opt; do
    case "$opt" in
        s) SIZE_THRESHOLD="$OPTARG" ;;
        o) OUTPUT="$OPTARG" ;;
        h) usage ;;
        *) echo "Unknown option: -$OPTARG" >&2; usage ;;
    esac
done
shift $(( OPTIND - 1 ))

if [[ $# -ne 1 ]]; then
    echo "Error: Exactly one directory argument required." >&2
    usage
fi

SEARCH_DIR="$1"

if [[ ! -d "$SEARCH_DIR" ]]; then
    echo "[!] Error: '$SEARCH_DIR' is not a valid directory." >&2
    exit 1
fi

# Validate size format — find(1) accepts optional leading + and suffix c/k/M/G
if [[ ! "$SIZE_THRESHOLD" =~ ^[0-9]+[ckMG]?$ ]]; then
    echo "[!] Error: Invalid size '$SIZE_THRESHOLD'. Use a number optionally followed by c, k, M, or G." >&2
    exit 1
fi

echo "[*] Searching for files larger than ${SIZE_THRESHOLD} in: $SEARCH_DIR"
echo "[*] Results will be saved to: $OUTPUT"
echo ""

{
    echo "======= Large File Scan ========"
    echo "Date:        $(date)"
    echo "Host:        $(hostname)"
    echo "User:        $(whoami)"
    echo "Search dir:  $SEARCH_DIR"
    echo "Threshold:   > ${SIZE_THRESHOLD}"
    echo "================================"
    echo ""

    find "$SEARCH_DIR" -type f -size "+${SIZE_THRESHOLD}" 2>/dev/null | sort | while read -r file; do
        # du -h gives human-readable size; stat gives owner/perms
        SIZE=$(du -sh "$file" 2>/dev/null | cut -f1)
        stat -c "%U %G %a  %-12s  %n" "$file" 2>/dev/null | \
            awk -v sz="$SIZE" '{$4=sz; print}' || true
    done
} | tee "$OUTPUT"

COUNT=$(grep -cP "^\S" "$OUTPUT" 2>/dev/null || echo 0)
# Subtract the 6 header lines
FILE_COUNT=$(( COUNT > 6 ? COUNT - 6 : 0 ))

echo ""
echo "[*] Scan complete: ${FILE_COUNT} file(s) found. Full results saved to: $OUTPUT"
