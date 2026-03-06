#!/bin/bash
# suid_finder.sh - Find all SUID files on the system
# Usage: sudo ./find_suid.sh [options]
#
# Options:
#   -d <dir>    Directory to search (default: /)
#   -o <file>   Output file path (default: /tmp/suid_files_<timestamp>.txt)
#   -a          Show last access time
#   -c          Show last change time (metadata)
#   -m          Show last modification time (content)
#   -h          Show this help message

SEARCH_DIR="/"
OUTPUT="/tmp/suid_files_$(date +%Y%m%d_%H%M%S).txt"
SHOW_ATIME=false
SHOW_CTIME=false
SHOW_MTIME=false

usage() {
    grep "^#" "$0" | grep -v "^#!/" | sed 's/^# \{0,1\}//'
    exit 0
}

while getopts "d:o:acmh" opt; do
    case "$opt" in
        d) SEARCH_DIR="$OPTARG" ;;
        o) OUTPUT="$OPTARG" ;;
        a) SHOW_ATIME=true ;;
        c) SHOW_CTIME=true ;;
        m) SHOW_MTIME=true ;;
        h) usage ;;
        *) echo "Unknown option: -$OPTARG" >&2; usage ;;
    esac
done

if [[ ! -d "$SEARCH_DIR" ]]; then
    echo "[!] Error: '$SEARCH_DIR' is not a valid directory." >&2
    exit 1
fi

echo "[*] Searching for SUID files in: $SEARCH_DIR"
echo "[*] Results will be saved to:    $OUTPUT"
echo ""

{
    echo "======= SUID File Scan ========"
    echo "Date:        $(date)"
    echo "Host:        $(hostname)"
    echo "User:        $(whoami)"
    echo "Search dir:  $SEARCH_DIR"
    echo "==============================="
    echo ""

    # Build stat format string dynamically
    # Base: owner group perms path
    STAT_FMT="%U %G %a %n"
    $SHOW_ATIME && STAT_FMT="$STAT_FMT\n    Access:   %x"
    $SHOW_MTIME && STAT_FMT="$STAT_FMT\n    Modify:   %y"
    $SHOW_CTIME && STAT_FMT="$STAT_FMT\n    Change:   %z"

    find "$SEARCH_DIR" -perm -4000 -type f 2>/dev/null | sort | while read -r file; do
        stat -c "$STAT_FMT" "$file" 2>/dev/null
    done
} | tee "$OUTPUT"

COUNT=$(grep -cP "^\S" "$OUTPUT" 2>/dev/null || echo 0)
# Subtract header lines (lines before the blank line after the header)
echo ""
echo "[*] Scan complete. Full results saved to: $OUTPUT"
