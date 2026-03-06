#!/bin/bash
# recent_finder.sh - Find files by timestamp within a relative time span
# Usage: ./recent_files.sh [-m] [-c] [-a] <directory> <timespan>
# Timespan examples: 8h, 30m, 2d, 1w

set -euo pipefail

USE_MTIME=false
USE_CTIME=false
USE_ATIME=false

usage() {
    echo "Usage: $0 [-m] [-c] [-a] <directory> <timespan>"
    echo ""
    echo "Flags (at least one required):"
    echo "  -m   Match/show mtime  (last content modification)"
    echo "  -c   Match/show ctime  (last metadata/content change — cannot be forged)"
    echo "  -a   Match/show atime  (last access/read)"
    echo ""
    echo "Timespan format: <number><unit>"
    echo "  Units: m (minutes), h (hours), d (days), w (weeks)"
    echo ""
    echo "Examples:"
    echo "  $0 -m   /var/log 8h     # mtime only"
    echo "  $0 -c   /etc     30m    # ctime only"
    echo "  $0 -mc  /home    2d     # mtime + ctime"
    echo "  $0 -mca /tmp     1h     # all three"
    exit 1
}

# Parse flags
while getopts ":mca" opt; do
    case "$opt" in
        m) USE_MTIME=true ;;
        c) USE_CTIME=true ;;
        a) USE_ATIME=true ;;
        *) echo "Error: Unknown flag -${OPTARG}" >&2; usage ;;
    esac
done
shift $(( OPTIND - 1 ))

# Require at least one flag
if ! $USE_MTIME && ! $USE_CTIME && ! $USE_ATIME; then
    echo "Error: At least one timestamp flag (-m, -c, -a) is required." >&2
    usage
fi

# Require directory and timespan positional args
if [[ $# -ne 2 ]]; then
    usage
fi

TARGET_DIR="$1"
TIMESPAN="$2"

if [[ ! -d "$TARGET_DIR" ]]; then
    echo "Error: '$TARGET_DIR' is not a directory or does not exist." >&2
    exit 1
fi

# Parse timespan
if [[ "$TIMESPAN" =~ ^([0-9]+)([mhdw])$ ]]; then
    AMOUNT="${BASH_REMATCH[1]}"
    UNIT="${BASH_REMATCH[2]}"
else
    echo "Error: Invalid timespan '$TIMESPAN'. Expected format like '8h', '30m', '2d', '1w'." >&2
    usage
fi

# Convert to minutes
case "$UNIT" in
    m) MINUTES="$AMOUNT" ;;
    h) MINUTES=$(( AMOUNT * 60 )) ;;
    d) MINUTES=$(( AMOUNT * 60 * 24 )) ;;
    w) MINUTES=$(( AMOUNT * 60 * 24 * 7 )) ;;
esac

# Build find expression — join selected flags with -o
FIND_EXPR=()
$USE_MTIME && FIND_EXPR+=( "-mmin" "-${MINUTES}" )
if $USE_CTIME; then
    [[ ${#FIND_EXPR[@]} -gt 0 ]] && FIND_EXPR+=( "-o" )
    FIND_EXPR+=( "-cmin" "-${MINUTES}" )
fi
if $USE_ATIME; then
    [[ ${#FIND_EXPR[@]} -gt 0 ]] && FIND_EXPR+=( "-o" )
    FIND_EXPR+=( "-amin" "-${MINUTES}" )
fi

# Build label for header
LABELS=()
$USE_MTIME && LABELS+=( "mtime" )
$USE_CTIME && LABELS+=( "ctime" )
$USE_ATIME && LABELS+=( "atime" )
LABEL_STR=$(IFS="|"; echo "${LABELS[*]}")

echo "Files matched by [${LABEL_STR}] in the last ${TIMESPAN} under: ${TARGET_DIR}"
echo "========================================================================"

RESULTS=$(find "$TARGET_DIR" -type f \( "${FIND_EXPR[@]}" \) 2>/dev/null | sort)

if [[ -z "$RESULTS" ]]; then
    echo "No files found."
else
    # Detect GNU vs BSD stat
    if stat --format='' /dev/null &>/dev/null; then
        STAT_GNU=true
    else
        STAT_GNU=false
    fi

    get_timestamps() {
        local file="$1"
        local out=()
        if $STAT_GNU; then
            $USE_MTIME && out+=( "mtime: $(stat --format='%y' "$file" 2>/dev/null)" )
            $USE_CTIME && out+=( "ctime: $(stat --format='%z' "$file" 2>/dev/null)" )
            $USE_ATIME && out+=( "atime: $(stat --format='%x' "$file" 2>/dev/null)" )
        else
            $USE_MTIME && out+=( "mtime: $(stat -f '%Sm' -t '%Y-%m-%d %H:%M:%S' "$file" 2>/dev/null)" )
            $USE_CTIME && out+=( "ctime: $(stat -f '%Sc' -t '%Y-%m-%d %H:%M:%S' "$file" 2>/dev/null)" )
            $USE_ATIME && out+=( "atime: $(stat -f '%Sa' -t '%Y-%m-%d %H:%M:%S' "$file" 2>/dev/null)" )
        fi
        (IFS=" | "; echo "${out[*]}")
    }

    while IFS= read -r file; do
        echo "$file"
        printf "  %s\n" "$(get_timestamps "$file")"
    done <<< "$RESULTS"

    COUNT=$(echo "$RESULTS" | wc -l)
    echo "========================================================================"
    echo "Total: ${COUNT} file(s)"
fi
