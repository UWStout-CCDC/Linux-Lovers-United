#!/usr/bin/env bash
# Usage: ./lsmod_report.sh

set -euo pipefail

echo "Kernel module modification report"
echo "Kernel: $(uname -r)"
echo "=================================================="
printf "%-45s  %-60s  %s\n" "Module" "Path" "Last Modified"
printf "%-45s  %-60s  %s\n" "------" "----" "-------------"

# Skip the header line, take the first column (module name)
while read -r module _rest; do
    # modinfo -n returns just the filename of the module
    if mod_path=$(modinfo -n "$module" 2>/dev/null) && [[ -n "$mod_path" ]]; then
        if [[ -f "$mod_path" ]]; then
            mtime=$(stat --format="%y" "$mod_path" 2>/dev/null | cut -d'.' -f1)
            printf "%-45s  %-60s  %s\n" "$module" "$mod_path" "$mtime"
        else
            printf "%-45s  %-60s  %s\n" "$module" "$mod_path" "[not found on disk]"
        fi
    else
        printf "%-45s  %-60s  %s\n" "$module" "[path unknown]" "[n/a]"
    fi
done < <(lsmod | tail -n +2)
