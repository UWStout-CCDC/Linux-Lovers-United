#!/usr/bin/env bash
# lsmod_report.sh - Kernel module report with selectable timestamps
# Usage: ./lsmod_report.sh [-m] [-c] [-a]

set -euo pipefail

USE_MTIME=false
USE_CTIME=false
USE_ATIME=false

usage() {
    echo "Usage: $0 [-m] [-c] [-a]"
    echo ""
    echo "Flags (at least one required):"
    echo "  -m   Show mtime  (last content modification)"
    echo "  -c   Show ctime  (last metadata/content change — cannot be forged)"
    echo "  -a   Show atime  (last access/read)"
    echo ""
    echo "Examples:"
    echo "  $0 -m        # mtime only"
    echo "  $0 -mc       # mtime + ctime"
    echo "  $0 -mca      # all three"
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

# Build timestamp label string for header
LABELS=()
$USE_MTIME && LABELS+=( "mtime" )
$USE_CTIME && LABELS+=( "ctime" )
$USE_ATIME && LABELS+=( "atime" )
LABEL_STR=$(IFS="|"; echo "${LABELS[*]}")

echo "Kernel module report  [${LABEL_STR}]"
echo "Kernel: $(uname -r)"
echo "========================================================================"
printf "%-40s  %-55s  %s\n" "Module" "Path" "Timestamp(s)"
printf "%-40s  %-55s  %s\n" "------" "----" "------------"

get_timestamps() {
    local file="$1"
    local out=()
    $USE_MTIME && out+=( "mtime: $(stat --format='%y' "$file" 2>/dev/null | cut -d'.' -f1)" )
    $USE_CTIME && out+=( "ctime: $(stat --format='%z' "$file" 2>/dev/null | cut -d'.' -f1)" )
    $USE_ATIME && out+=( "atime: $(stat --format='%x' "$file" 2>/dev/null | cut -d'.' -f1)" )
    (IFS=" | "; echo "${out[*]}")
}

while read -r module _rest; do
    if mod_path=$(modinfo -n "$module" 2>/dev/null) && [[ -n "$mod_path" ]]; then
        if [[ -f "$mod_path" ]]; then
            timestamps=$(get_timestamps "$mod_path")
            printf "%-40s  %-55s  %s\n" "$module" "$mod_path" "$timestamps"
        else
            printf "%-40s  %-55s  %s\n" "$module" "$mod_path" "[not found on disk]"
        fi
    else
        printf "%-40s  %-55s  %s\n" "$module" "[path unknown]" "[n/a]"
    fi
done < <(lsmod | tail -n +2)
