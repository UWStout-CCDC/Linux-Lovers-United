#!/bin/bash
# ==============================================================================
# auth_report.sh — SSH / Login Session Parser
# Blue team / CCDC defensive tool
#
# Parses /var/log/auth.log (Debian/Ubuntu) or /var/log/secure (RHEL/CentOS)
# and produces a per-session report including:
#   - Login time, source IP, username, and auth method
#   - Privileged commands (sudo, su) executed during the session
#   - Logoff time (or flags the session as still open)
#
# Note: auth.log / secure only record sudo/su commands, NOT raw shell history.
#       For full command history, cross-reference ~/.bash_history or auditd logs.
#
# Usage:
#   sudo ./auth_report.sh [OPTIONS]
#
# Options:
#   -f <file>   Log file to parse (auto-detected if omitted)
#   -u <user>   Filter output to sessions for this username only
#   -i <ip>     Filter output to sessions from this source IP only
#   -o <file>   Output file (default: /tmp/auth_report_<timestamp>.txt)
#   -h          Show this help message
#
# Examples:
#   sudo ./auth_report.sh
#   sudo ./auth_report.sh -u root
#   sudo ./auth_report.sh -i 10.0.0.5 -o /tmp/suspicious.txt
#   sudo ./auth_report.sh -f /var/log/auth.log.1
# ==============================================================================

set -uo pipefail

# ---------------------------------------------------------------------------- #
# Defaults
# ---------------------------------------------------------------------------- #
LOG_FILE=""
FILTER_USER=""
FILTER_IP=""
OUTPUT="/tmp/auth_report_$(date +%Y%m%d_%H%M%S).txt"

# ---------------------------------------------------------------------------- #
# Arg parsing
# ---------------------------------------------------------------------------- #
usage() {
    grep '^#' "$0" | grep -v '#!/' | sed 's/^# \{0,\}//'
    exit 0
}

while getopts "f:u:i:o:h" opt; do
    case "$opt" in
        f) LOG_FILE="$OPTARG"   ;;
        u) FILTER_USER="$OPTARG" ;;
        i) FILTER_IP="$OPTARG"  ;;
        o) OUTPUT="$OPTARG"     ;;
        h) usage                ;;
        *) echo "[!] Unknown option: -$OPTARG" >&2; usage ;;
    esac
done

# ---------------------------------------------------------------------------- #
# Auto-detect log file
# ---------------------------------------------------------------------------- #
if [[ -z "$LOG_FILE" ]]; then
    if   [[ -f /var/log/auth.log ]]; then LOG_FILE="/var/log/auth.log"
    elif [[ -f /var/log/secure   ]]; then LOG_FILE="/var/log/secure"
    else
        echo "[!] Could not find /var/log/auth.log or /var/log/secure." >&2
        echo "    On systemd-only systems use: journalctl -u sshd --no-pager" >&2
        echo "    Or specify a log file with -f <file>." >&2
        exit 1
    fi
fi

[[ ! -f "$LOG_FILE" ]] && { echo "[!] Log file '$LOG_FILE' not found." >&2; exit 1; }
[[ ! -r "$LOG_FILE" ]] && { echo "[!] Cannot read '$LOG_FILE'. Try running with sudo." >&2; exit 1; }

# ---------------------------------------------------------------------------- #
# Report
# ---------------------------------------------------------------------------- #
echo "[*] Parsing:  $LOG_FILE"
echo "[*] Output:   $OUTPUT"
[[ -n "$FILTER_USER" ]] && echo "[*] User:     $FILTER_USER"
[[ -n "$FILTER_IP"   ]] && echo "[*] IP:       $FILTER_IP"
echo ""

{
    echo "========================================"
    echo " Auth Session Report"
    echo "========================================"
    echo " Date:    $(date)"
    echo " Host:    $(hostname)"
    echo " Log:     $LOG_FILE"
    [[ -n "$FILTER_USER" ]] && echo " User:    $FILTER_USER"
    [[ -n "$FILTER_IP"   ]] && echo " IP:      $FILTER_IP"
    echo "========================================"
    echo ""
    echo " NOTE: 'Commands' reflects only sudo/su activity recorded in auth logs."
    echo "       For raw shell history, check ~/.bash_history or auditd logs."
    echo ""

    # ---------------------------------------------------------------------- #
    # AWK: single-pass session parser
    #
    # Patterns handled:
    #   SSH login    — sshd[PID]: Accepted <method> for <user> from <ip> ...
    #   Console login — pam_unix(<svc>:session): session opened for user <user>
    #   Sudo command  — sudo[PID]: <user> : TTY=... ; ... ; COMMAND=<cmd>
    #   Su (success)  — su[PID]: Successful su for <runas> by <user>
    #   Session close — pam_unix(<svc>:session): session closed for user <user>
    #
    # Session correlation: PIDs are used to match opens/closes.
    # Sudo/su commands are attributed to the most recent open session for
    # that username (since sudo runs under a child PID, not the sshd PID).
    # ---------------------------------------------------------------------- #
    awk -v fuser="$FILTER_USER" -v fip="$FILTER_IP" '

    # Extract numeric PID from "process[1234]:" field
    function get_pid(field,   p) {
        p = field
        gsub(/.*\[/, "", p)
        gsub(/\].*/, "", p)
        return p
    }

    # Build a timestamp string from the first three fields (syslog format)
    function ts() {
        return sprintf("%s %2s %s", $1, $2, $3)
    }

    # Output a completed session block, applying any active filters
    function print_session(pid,   logout, line) {
        u  = s_user[pid]
        ip = s_ip[pid]
        if (fuser != "" && u  != fuser) return
        if (fip   != "" && ip != fip  ) return

        logout = (s_logout[pid] != "") ? s_logout[pid] : "(session still open or log ends)"

        print "=== Session =============================="
        printf "  User:     %s\n", u
        printf "  Source:   %s  [%s]\n", ip, s_method[pid]
        printf "  Login:    %s\n", s_login[pid]
        printf "  Logout:   %s\n", logout

        if (s_cmds[pid] == "") {
            print "  Commands: (none logged)"
        } else {
            print "  Commands:"
            printf "%s", s_cmds[pid]
        }
        print ""
        sess_count++
    }

    # ------------------------------------------------------------------ #
    # SSH accepted login
    # Format: sshd[PID]: Accepted <method> for <user> from <ip> port ...
    # ------------------------------------------------------------------ #
    /sshd\[[0-9]+\]:.*Accepted / {
        pid = get_pid($5)
        for (i = 6; i <= NF; i++) {
            if ($i == "for") {
                s_user[pid]   = $(i+1)
                s_ip[pid]     = $(i+3)
                s_method[pid] = $(i-1)
                break
            }
        }
        s_login[pid]  = ts()
        s_logout[pid] = ""
        s_cmds[pid]   = ""
        s_open[pid]   = 1
        u = s_user[pid]
        u_pids[u] = (u in u_pids) ? u_pids[u] "," pid : pid
    }

    # ------------------------------------------------------------------ #
    # Console / service login (login, su, cron, etc. — not sshd)
    # Format: process[PID]: pam_unix(<svc>:session): session opened for user <user>
    # ------------------------------------------------------------------ #
    /pam_unix\(.*:session\): session opened for user/ {
        pid  = get_pid($5)
        proc = $5; gsub(/\[.*/, "", proc)

        # SSH sessions are already captured from the Accepted line.
        # sudo creates a transient PAM session for the target user on every
        # invocation — exclude it here; the command is captured separately.
        if (proc == "sshd" || proc == "sudo" || (pid in s_open)) next

        for (i = 6; i <= NF; i++) {
            if ($i == "user") { user = $(i+1); break }
        }
        s_user[pid]   = user
        s_ip[pid]     = "local"
        s_method[pid] = proc
        s_login[pid]  = ts()
        s_logout[pid] = ""
        s_cmds[pid]   = ""
        s_open[pid]   = 1
        u_pids[user]  = (user in u_pids) ? u_pids[user] "," pid : pid
    }

    # ------------------------------------------------------------------ #
    # Sudo command
    # Format: sudo[PID]: <user> : TTY=... ; PWD=... ; USER=<runas> ; COMMAND=<cmd>
    # ------------------------------------------------------------------ #
    /sudo\[[0-9]+\]:/ && /; COMMAND=/ {
        user = $6; runas = ""; cmd = ""
        for (i = 7; i <= NF; i++) {
            if ($i ~ /^USER=/) {
                runas = substr($i, 6)
                gsub(/;$/, "", runas)
            }
            if ($i ~ /^COMMAND=/) {
                cmd = substr($i, 9)
                for (j = i+1; j <= NF; j++) cmd = cmd " " $j
                break
            }
        }
        entry = "    [" ts() "] sudo -> " runas ": " cmd "\n"
        attributed = 0
        if (user in u_pids) {
            n = split(u_pids[user], plist, ",")
            for (k = n; k >= 1; k--) {
                p = plist[k]
                if ((p in s_open) && s_open[p] == 1) { s_cmds[p] = s_cmds[p] entry; attributed = 1; break }
            }
        }
        if (!attributed) orphan_cmds[user] = orphan_cmds[user] entry
    }

    # ------------------------------------------------------------------ #
    # Su (successful)
    # Format: su[PID]: Successful su for <runas> by <user>
    # ------------------------------------------------------------------ #
    /su\[[0-9]+\]:.*Successful su for/ {
        runas = ""; user = ""
        for (i = 6; i <= NF; i++) {
            if ($i == "for") runas = $(i+1)
            if ($i == "by")  user  = $(i+1)
        }
        if (user == "" || runas == "") next
        entry = "    [" ts() "] su -> " runas "\n"
        attributed = 0
        if (user in u_pids) {
            n = split(u_pids[user], plist, ",")
            for (k = n; k >= 1; k--) {
                p = plist[k]
                if ((p in s_open) && s_open[p] == 1) { s_cmds[p] = s_cmds[p] entry; attributed = 1; break }
            }
        }
        if (!attributed) orphan_cmds[user] = orphan_cmds[user] entry
    }

    # ------------------------------------------------------------------ #
    # Session close
    # Format: process[PID]: pam_unix(<svc>:session): session closed for user <user>
    # ------------------------------------------------------------------ #
    /pam_unix\(.*:session\): session closed for user/ {
        pid = get_pid($5)
        if (!((pid in s_open) && s_open[pid] == 1)) next
        s_logout[pid] = ts()
        s_open[pid]   = 0
        print_session(pid)
    }

    # ------------------------------------------------------------------ #
    # End: flush any sessions with no matching close (still open / log cut off)
    # ------------------------------------------------------------------ #
    END {
        # Flush open sessions (no matching close found)
        for (pid in s_open) {
            if (s_open[pid] == 1) print_session(pid)
        }

        # Orphaned commands: sudo/su with no matching tracked login session.
        # Common causes: session started before log rotation, or service accounts
        # that log in via a mechanism not captured by auth.log (e.g. PAM service
        # running without a full pty session).
        for (u in orphan_cmds) {
            if (fuser != "" && u != fuser) continue
            print "=== Unattributed Commands ================"
            printf "  User:   %s\n", u
            print "  Source: (no login session found in this log)"
            print "  Commands:"
            printf "%s", orphan_cmds[u]
            print ""
            orphan_count++
        }

        print "========================================"
        if (sess_count == 0 && orphan_count == 0) {
            print " No sessions matched."
            print " If the log exists but is empty, verify syslog is forwarding"
            print " auth events (rsyslog/syslog-ng). Systemd-only installs may"
            print " require: journalctl -u sshd --no-pager"
        } else {
            printf " Sessions:             %d\n", sess_count
            printf " Unattributed users:   %d\n", orphan_count
        }
        print "========================================"
    }
    ' "$LOG_FILE"

} | tee "$OUTPUT"

echo ""
echo "[*] Report saved to: $OUTPUT"
