#!/bin/bash
# ==============================================================================
# beacon-monitor.sh — C2 Beacon Detection & Traffic Tracer
# Blue team / CCDC defensive tool
#
# Detects:
#   - Beaconing patterns (periodic connections to same dst, NOT established)
#   - DNS traffic / DNS tunneling indicators
#   - HTTP C2 (Host headers, URIs)
#   - HTTPS C2 (TLS SNI from ClientHello)
#   - Suspicious port traffic (all TCP/UDP ports monitored; known C2 ports get priority alerts)
#
# Usage:
#   sudo ./beacon-monitor.sh [OPTIONS]
#
# Options:
#   -i <iface>       Interface to monitor (default: auto-detect)
#   -o <dir>         Output directory (default: ./beacon-logs)
#   -w <seconds>     Beacon detection window (default: 120s)
#   -t <count>       Connections to same dst to flag as beacon (default: 3)
#   -p <seconds>     Connection poll interval (default: 5s)
#   -f <ports>       Force-alert on specific ports regardless of range (e.g. 80,443 for C2-over-HTTP/S)
#   -a <file>        Also write all alerts to this specific file (e.g. /var/log/c2-alerts.log)
#   -v               Verbose output to stdout
#   -h               Show this help
# ==============================================================================

set -uo pipefail

# ---------------------------------------------------------------------------- #
# Defaults
# ---------------------------------------------------------------------------- #
IFACE=""
OUTPUT_DIR="./beacon-logs"
BEACON_WINDOW=120        # seconds to accumulate connection events per dst
BEACON_THRESHOLD=3       # repeated contacts to same dst:port to flag
POLL_INTERVAL=5          # ss polling interval in seconds
EXTRA_PORTS=""
ALERT_FILE=""       # optional: also write alerts to a specific file path
VERBOSE=false

# Port range that triggers alerts — default: all non-privileged ports (1024-65535)
# Use -f to force-alert on ports below this range (e.g. 80, 443)
ALERT_PORT_MIN=1024
ALERT_PORT_MAX=65535

# Sliver-specific indicators
SLIVER_PORTS="80 443 8080 8443 8888 31337"
SLIVER_DNS_PATTERNS="(implant|beacon|agent|stage|sl[0-9a-f]{8})"

# ---------------------------------------------------------------------------- #
# Arg parsing
# ---------------------------------------------------------------------------- #
usage() {
    grep '^#' "$0" | grep -v '#!/' | sed 's/^# \{0,\}//'
    exit 0
}

while getopts "i:o:w:t:p:f:a:vh" opt; do
    case $opt in
        i) IFACE="$OPTARG" ;;
        o) OUTPUT_DIR="$OPTARG" ;;
        w) BEACON_WINDOW="$OPTARG" ;;
        t) BEACON_THRESHOLD="$OPTARG" ;;
        p) POLL_INTERVAL="$OPTARG" ;;
        f) EXTRA_PORTS="$OPTARG" ;;
        a) ALERT_FILE="$OPTARG" ;;
        v) VERBOSE=true ;;
        h) usage ;;
        *) echo "Unknown option: -$OPTARG" >&2; exit 1 ;;
    esac
done

# ---------------------------------------------------------------------------- #
# Setup
# ---------------------------------------------------------------------------- #
[[ $EUID -ne 0 ]] && echo "[!] Root required for packet capture. Run with sudo." && exit 1

# Auto-detect interface
if [[ -z "$IFACE" ]]; then
    IFACE=$(ip route get 8.8.8.8 2>/dev/null | awk '/dev/ {for(i=1;i<=NF;i++) if($i=="dev") print $(i+1)}' | head -1)
    [[ -z "$IFACE" ]] && IFACE=$(ip link show | awk -F': ' '/^[0-9]+: [^lo]/ {print $2; exit}')
    [[ -z "$IFACE" ]] && { echo "[!] Could not auto-detect interface. Use -i <iface>"; exit 1; }
fi

# Validate user-specified alert file is writable
if [[ -n "$ALERT_FILE" ]]; then
    touch "$ALERT_FILE" 2>/dev/null || {
        echo "[!] Cannot write to alert file: $ALERT_FILE"
        exit 1
    }
    echo "# C2 Beacon Alerts — started $(ts)" >> "$ALERT_FILE"
fi

# Build force-alert port list from -f flag (ports to alert on regardless of range)
FORCE_ALERT_PORTS=""
FORCE_ALERT_REGEX=""
if [[ -n "$EXTRA_PORTS" ]]; then
    FORCE_ALERT_PORTS=$(echo "$EXTRA_PORTS" | tr ',' ' ')
    FORCE_ALERT_REGEX="^($(echo "$FORCE_ALERT_PORTS" | tr ' ' '|'))$"
fi

# Create output directory structure
mkdir -p "$OUTPUT_DIR"/{dns,http,https,c2ports,connections,beacons,pcap}

TIMESTAMP=$(date +%Y%m%d_%H%M%S)
LOG_DNS="$OUTPUT_DIR/dns/dns_${TIMESTAMP}.log"
LOG_HTTP="$OUTPUT_DIR/http/http_${TIMESTAMP}.log"
LOG_HTTPS="$OUTPUT_DIR/https/https_${TIMESTAMP}.log"
LOG_C2="$OUTPUT_DIR/c2ports/c2ports_${TIMESTAMP}.log"
LOG_CONNS="$OUTPUT_DIR/connections/connections_${TIMESTAMP}.log"
LOG_BEACONS="$OUTPUT_DIR/beacons/beacons_${TIMESTAMP}.log"
LOG_SUMMARY="$OUTPUT_DIR/SUMMARY_${TIMESTAMP}.log"

# Track child PIDs for cleanup
CHILD_PIDS=()

# ---------------------------------------------------------------------------- #
# Helpers
# ---------------------------------------------------------------------------- #
ts() { date '+%Y-%m-%d %H:%M:%S'; }

log() {
    local level="$1"; shift
    local msg="[$(ts)] [$level] $*"
    echo "$msg" >> "$LOG_SUMMARY"
    $VERBOSE && echo "$msg"
}

alert() {
    local msg="[$(ts)] [ALERT] $*"
    echo "$msg" | tee -a "$LOG_SUMMARY" "$LOG_BEACONS"
    # Write to user-specified alert file if set
    [[ -n "$ALERT_FILE" ]] && echo "$msg" >> "$ALERT_FILE"
    # Also print to stderr so it's visible even without -v
    echo "$msg" >&2
}

check_tool() {
    command -v "$1" &>/dev/null
}

cleanup() {
    log INFO "Shutting down monitors..."
    for pid in "${CHILD_PIDS[@]:-}"; do
        kill "$pid" 2>/dev/null || true
    done
    log INFO "Logs saved to: $OUTPUT_DIR"
    echo ""
    echo "[*] Monitor stopped. Logs in: $OUTPUT_DIR"
    echo "[*] Summary:  $LOG_SUMMARY"
    echo "[*] Beacons:  $LOG_BEACONS"
}
trap cleanup EXIT INT TERM

# ---------------------------------------------------------------------------- #
# Tool detection
# ---------------------------------------------------------------------------- #
HAS_TSHARK=false
HAS_TCPDUMP=false
HAS_SS=false
HAS_NETSTAT=false

check_tool tshark   && HAS_TSHARK=true
check_tool tcpdump  && HAS_TCPDUMP=true
check_tool ss       && HAS_SS=true
check_tool netstat  && HAS_NETSTAT=true

if ! $HAS_TSHARK && ! $HAS_TCPDUMP; then
    echo "[!] Neither tshark nor tcpdump found. Install wireshark-cli or tcpdump."
    exit 1
fi

if ! $HAS_SS && ! $HAS_NETSTAT; then
    echo "[!] Neither ss nor netstat found. Connection monitoring unavailable."
fi

# ---------------------------------------------------------------------------- #
# Banner
# ---------------------------------------------------------------------------- #
cat <<EOF
╔══════════════════════════════════════════════════════════╗
║          C2 BEACON MONITOR — Blue Team / CCDC            ║
╚══════════════════════════════════════════════════════════╝
  Interface:        $IFACE
  Output dir:       $OUTPUT_DIR
  Beacon window:    ${BEACON_WINDOW}s
  Beacon threshold: ${BEACON_THRESHOLD} contacts
  Poll interval:    ${POLL_INTERVAL}s
  Port coverage:    all TCP/UDP ports 1-65535 (DNS handled by DNS monitor)
  Alert range:      ports ${ALERT_PORT_MIN}-${ALERT_PORT_MAX}
  Force-alert ports:${FORCE_ALERT_PORTS:-" (none — use -f to add specific ports)"}
  tshark available: $HAS_TSHARK
  tcpdump avail:    $HAS_TCPDUMP
  Alert file:       ${ALERT_FILE:-"(none — use -a <file>)"}
  Started:          $(ts)
──────────────────────────────────────────────────────────
EOF

log INFO "Monitor started on interface $IFACE"

# ---------------------------------------------------------------------------- #
# 1. DNS Monitor
#    Logs: timestamp, query_type, queried_name, response_ip, src_ip
#    Flags: long labels (DNS tunnel), high-entropy subdomains, known C2 patterns
# ---------------------------------------------------------------------------- #
start_dns_monitor() {
    log INFO "Starting DNS monitor -> $LOG_DNS"

    echo "# DNS Monitor — $(ts) — Interface: $IFACE" > "$LOG_DNS"
    echo "# FORMAT: timestamp|src_ip|query_type|query_name|response_ips|flags" >> "$LOG_DNS"

    if $HAS_TSHARK; then
        tshark -i "$IFACE" -l -n \
            -f "port 53" \
            -T fields \
            -e frame.time_epoch \
            -e ip.src \
            -e dns.qry.type \
            -e dns.qry.name \
            -e dns.a \
            -E separator='|' \
            2>/dev/null | \
        awk -F'|' '
        {
            ts=$1; src=$2; qtype=$3; name=$4; resp=$5
            flags=""

            # Flag long labels (DNS tunneling indicator: labels > 52 chars)
            n=split(name, parts, ".")
            for (i=1; i<=n; i++) {
                if (length(parts[i]) > 52) {
                    flags=flags"LONG_LABEL "
                }
            }

            # Flag high subdomain depth (>5 labels)
            if (n > 5) flags=flags"DEEP_SUBDOMAIN "

            # Flag name length > 100 chars (tunneling)
            if (length(name) > 100) flags=flags"LONG_NAME "

            # Flag known C2/beacon pattern keywords
            if (name ~ /implant|beacon|agent|stage|c2|call(back|home)|update\.(php|aspx)/) {
                flags=flags"C2_KEYWORD "
            }

            # Flag numeric-heavy subdomains (base32/64 encoded tunnels)
            if (parts[1] ~ /^[a-z0-9]{20,}$/) flags=flags"HIGH_ENTROPY_LABEL "

            printf "%s|%s|%s|%s|%s|%s\n", ts, src, qtype, name, resp, flags

            if (flags != "") {
                printf "[ALERT] DNS anomaly: %s queried %s [%s]\n", src, name, flags | "cat >&2"
            }
        }' >> "$LOG_DNS" &
    else
        # tcpdump fallback — less detail but functional
        tcpdump -i "$IFACE" -l -n -tttt "port 53" 2>/dev/null | \
        awk '{
            ts=$1" "$2
            if (/A\?/) {
                match($0, /A\? ([^ ]+)/, m)
                name=m[1]
                if (length(name) > 100) print ts"|DNS_LONG_NAME|"name
                else print ts"|DNS|"name
            }
        }' >> "$LOG_DNS" &
    fi

    CHILD_PIDS+=($!)
    log INFO "DNS monitor PID: $!"
}

# ---------------------------------------------------------------------------- #
# 2. HTTP Monitor
#    Extracts: Host header, URI, User-Agent, src:dst
#    Flags: suspicious user agents, beaconing URIs, Sliver default paths
# ---------------------------------------------------------------------------- #
start_http_monitor() {
    log INFO "Starting HTTP monitor -> $LOG_HTTP"

    echo "# HTTP Monitor — $(ts) — Interface: $IFACE" > "$LOG_HTTP"
    echo "# FORMAT: timestamp|src_ip|dst_ip:port|method|host|uri|user_agent|flags" >> "$LOG_HTTP"

    if $HAS_TSHARK; then
        tshark -i "$IFACE" -l -n \
            -f "tcp port 80 or tcp port 8080" \
            -Y "http.request" \
            -T fields \
            -e frame.time_epoch \
            -e ip.src \
            -e ip.dst \
            -e tcp.dstport \
            -e http.request.method \
            -e http.host \
            -e http.request.uri \
            -e http.user_agent \
            -E separator='|' \
            2>/dev/null | \
        awk -F'|' '
        {
            ts=$1; src=$2; dst=$3; dport=$4
            method=$5; host=$6; uri=$7; ua=$8
            flags=""

            # Sliver default HTTP C2 paths
            if (uri ~ /\/[a-z]{1,5}\.(php|html|js|png|gif)$/ && length(uri) < 25) {
                flags=flags"SLIVER_URI_PATTERN "
            }

            # Very short/generic URIs used by beacons
            if (uri ~ /^\/(index\.(php|html|aspx?)|updates?|check(in)?|poll|ping|beacon)\b/) {
                flags=flags"BEACON_URI "
            }

            # Suspicious or absent User-Agent
            if (ua == "" || ua ~ /^Go-http-client|curl|python|wget|powershell|WinHttp/) {
                flags=flags"SUSPICIOUS_UA "
            }

            # Base64-like or long random URI components (encoded beacon data)
            if (uri ~ /\/[A-Za-z0-9+\/]{40,}/) flags=flags"ENCODED_URI "

            printf "%s|%s|%s:%s|%s|%s|%s|%s|%s\n",
                ts, src, dst, dport, method, host, uri, ua, flags
        }' >> "$LOG_HTTP" &
    else
        tcpdump -i "$IFACE" -l -n -A "tcp port 80 or tcp port 8080" 2>/dev/null | \
        grep -E "^(GET|POST|PUT|HEAD|Host:|User-Agent:)" >> "$LOG_HTTP" &
    fi

    CHILD_PIDS+=($!)
    log INFO "HTTP monitor PID: $!"
}

# ---------------------------------------------------------------------------- #
# 3. HTTPS/TLS Monitor
#    Extracts TLS SNI from ClientHello (no decryption needed)
#    Flags: self-signed certs, missing SNI, Sliver default cert fingerprints
# ---------------------------------------------------------------------------- #
start_https_monitor() {
    log INFO "Starting HTTPS/TLS monitor -> $LOG_HTTPS"

    echo "# HTTPS/TLS Monitor — $(ts) — Interface: $IFACE" > "$LOG_HTTPS"
    echo "# FORMAT: timestamp|src_ip|dst_ip:port|tls_sni|tls_version|ja3|flags" >> "$LOG_HTTPS"

    if $HAS_TSHARK; then
        tshark -i "$IFACE" -l -n \
            -f "tcp port 443 or tcp port 8443" \
            -Y "tls.handshake.type == 1" \
            -T fields \
            -e frame.time_epoch \
            -e ip.src \
            -e ip.dst \
            -e tcp.dstport \
            -e tls.handshake.extensions_server_name \
            -e tls.handshake.version \
            -e tls.handshake.ja3 \
            -E separator='|' \
            2>/dev/null | \
        awk -F'|' '
        {
            ts=$1; src=$2; dst=$3; dport=$4
            sni=$5; tls_ver=$6; ja3=$7
            flags=""

            # Missing SNI is suspicious (beacon connecting to IP, not domain)
            if (sni == "") flags=flags"NO_SNI "

            # IP address as SNI destination (direct C2 IP contact)
            if (dst ~ /^[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+$/ && sni == "") {
                flags=flags"DIRECT_IP_TLS "
            }

            # Known Sliver C2 JA3 hashes (Go TLS client fingerprint)
            # These are common Go/Sliver JA3 signatures
            if (ja3 ~ /^(513d9aaef45e0bc0d82e4f14c1b1a3ce|b32309a26951912be7dba376398abc3b|aaa7579f7e9d0dd29a24f8e8e0aebe55)/) {
                flags=flags"SLIVER_JA3 "
            }

            # Generic Go TLS client (used by Sliver, Metasploit, many beacons)
            if (ja3 ~ /^(0d7f493f71c843a1e49e3e3cf90c2a31|e7d705a3286e19ea42f587b6)/) {
                flags=flags"GO_TLS_CLIENT "
            }

            printf "%s|%s|%s:%s|%s|%s|%s|%s\n",
                ts, src, dst, dport, sni, tls_ver, ja3, flags
        }' >> "$LOG_HTTPS" &
    else
        # tcpdump fallback: capture TLS ClientHello (content type 22, handshake type 1)
        tcpdump -i "$IFACE" -l -n "tcp port 443 or tcp port 8443 and (tcp[((tcp[12:1] & 0xf0) >> 2):1] = 22)" \
            2>/dev/null >> "$LOG_HTTPS" &
    fi

    CHILD_PIDS+=($!)
    log INFO "HTTPS/TLS monitor PID: $!"
}

# ---------------------------------------------------------------------------- #
# 4. Suspicious Port Monitor
#    Watches for traffic on known C2/implant ports
# ---------------------------------------------------------------------------- #

# Resolve the process/exe owning a src IP:port connection via ss.
# Usage: lookup_proc <src_ip> <src_port>
# Outputs: "pid=X name=Y exe=/path/to/binary"
lookup_proc() {
    local src_ip="$1"
    local src_port="$2"
    local info pid proc_name exe_path

    # ss with source filter is fast; fall back to full scan if it returns nothing
    info=$(ss -tunap "src ${src_ip}:${src_port}" 2>/dev/null | awk 'NR>1 {print $7; exit}')
    [[ -z "$info" ]] && \
        info=$(ss -tunap 2>/dev/null | awk -v a="${src_ip}:${src_port}" '$5==a{print $7;exit}')

    pid=$(echo "$info" | grep -oP 'pid=\K[0-9]+' | head -1)
    if [[ -n "$pid" ]]; then
        proc_name=$(echo "$info" | grep -oP '"\K[^"]+' | head -1)
        exe_path=$(readlink -f "/proc/$pid/exe" 2>/dev/null || echo "unknown")
        echo "pid=$pid name=${proc_name:-?} exe=$exe_path"
    else
        echo "exe=unknown (process may have already exited)"
    fi
}

start_c2port_monitor() {
    log INFO "Starting full-range port monitor (all TCP/UDP) -> $LOG_C2"

    echo "# Port Monitor — $(ts) — Interface: $IFACE" > "$LOG_C2"
    echo "# Coverage: all TCP/UDP ports 1-65535 (port 53/DNS handled by DNS monitor)" >> "$LOG_C2"
    echo "# Alert range: ports ${ALERT_PORT_MIN}-${ALERT_PORT_MAX} | Force-alert: ${FORCE_ALERT_PORTS:-none}" >> "$LOG_C2"
    echo "# FORMAT: timestamp|label|src_ip:port|dst_ip:port|protocol|size|proc_info" >> "$LOG_C2"

    # Capture all TCP/UDP — exclude port 53 (handled by dedicated DNS monitor)
    PORT_FILTER="(tcp or udp) and not port 53"

    if $HAS_TSHARK; then
        tshark -i "$IFACE" -l -n \
            -f "$PORT_FILTER" \
            -T fields \
            -e frame.time_epoch \
            -e ip.src \
            -e ip.dst \
            -e tcp.srcport \
            -e tcp.dstport \
            -e udp.srcport \
            -e udp.dstport \
            -e frame.protocols \
            -e frame.len \
            -E separator='|' \
            2>/dev/null | \
        while IFS='|' read -r ts src_ip dst_ip tcp_sport tcp_dport udp_sport udp_dport protos len; do
            src_port="${tcp_sport:-$udp_sport}"
            dst_port="${tcp_dport:-$udp_dport}"
            proc_info=$(lookup_proc "$src_ip" "$src_port")
            if (( dst_port >= ALERT_PORT_MIN && dst_port <= ALERT_PORT_MAX )) || \
               { [[ -n "$FORCE_ALERT_REGEX" ]] && [[ "$dst_port" =~ $FORCE_ALERT_REGEX ]]; }; then
                msg="HIGH-PORT: $src_ip:$src_port -> $dst_ip:$dst_port | $protos | ${len}B | $proc_info"
                echo "[$(ts)] $msg" >> "$LOG_C2"
                alert "$msg"
            else
                echo "[$(ts)] TRAFFIC: $src_ip:$src_port -> $dst_ip:$dst_port | $protos | ${len}B | $proc_info" >> "$LOG_C2"
            fi
        done &
    else
        # -nn: suppress both hostname AND port-name resolution so we get numeric ports
        tcpdump -i "$IFACE" -l -nn -tttt "$PORT_FILTER" 2>/dev/null | \
        while read -r _date _time _proto src_addr _arrow dst_addr rest; do
            # tcpdump format: DATE TIME IP src.port > dst.port: ...
            src_ip="${src_addr%.*}"
            src_port="${src_addr##*.}"
            dst_ip="${dst_addr%.*}"
            dst_port="${dst_addr##*.}"
            dst_port="${dst_port%:}"   # strip trailing colon
            proc_info=$(lookup_proc "$src_ip" "$src_port")
            if (( dst_port >= ALERT_PORT_MIN && dst_port <= ALERT_PORT_MAX )) || \
               { [[ -n "$FORCE_ALERT_REGEX" ]] && [[ "$dst_port" =~ $FORCE_ALERT_REGEX ]]; }; then
                msg="HIGH-PORT: $src_ip:$src_port -> $dst_ip:$dst_port | $proc_info | $rest"
                echo "[$(ts)] $msg" >> "$LOG_C2"
                alert "$msg"
            else
                echo "[$(ts)] TRAFFIC: $src_ip:$src_port -> $dst_ip:$dst_port | $proc_info | $rest" >> "$LOG_C2"
            fi
        done &
    fi

    CHILD_PIDS+=($!)
    log INFO "Port monitor PID: $!"
}

# ---------------------------------------------------------------------------- #
# 5. Connection State Monitor (Beacon Pattern Detection)
#    Polls ss/netstat to find:
#      - SYN_SENT connections (outbound connection attempts)
#      - TIME_WAIT clusters to same destination (repeated short connections)
#      - Connections NOT in ESTABLISHED state (beacon callbacks)
# ---------------------------------------------------------------------------- #

# Associative array to track connection attempts: [dst_ip:port] -> timestamps
declare -A CONN_COUNTS
declare -A CONN_FIRST_SEEN
declare -A CONN_LAST_SEEN
declare -A CONN_PROC     # stores most-recent proc string per dst key

start_connection_monitor() {
    log INFO "Starting connection state monitor -> $LOG_CONNS"

    echo "# Connection Monitor — $(ts) — Interface: $IFACE" > "$LOG_CONNS"
    echo "# FORMAT: timestamp|state|src_ip:port|dst_ip:port|process" >> "$LOG_CONNS"

    (
        while true; do
            NOW=$(date +%s)

            if $HAS_SS; then
                # Capture all TCP connections — focus on non-ESTABLISHED outbound
                ss -tunap 2>/dev/null | awk '
                NR > 1 {
                    proto=$1; state=$2; src=$5; dst=$6; proc=$7
                    # Skip purely ESTABLISHED (those are normal sessions)
                    # We want SYN-SENT, TIME-WAIT, CLOSE-WAIT, FIN-WAIT
                    if (state != "ESTABLISHED" && state != "LISTEN") {
                        print proto"|"state"|"src"|"dst"|"proc
                    }
                    # Also include ESTABLISHED connections to suspicious ports
                    if (state == "ESTABLISHED") {
                        split(dst, d, ":")
                        port=d[length(d)]
                        if (port+0 > 0) {
                            # Flag non-standard high ports in ESTABLISHED state
                            if ((port > 1024 && port != 8080 && port != 8443 &&
                                 port != 443 && port != 80 && port != 22 &&
                                 port != 25 && port != 587 && port != 993) &&
                                proto == "tcp") {
                                print proto"|ESTABLISHED-SUSPICIOUS|"src"|"dst"|"proc
                            }
                        }
                    }
                }'
            elif $HAS_NETSTAT; then
                netstat -tunap 2>/dev/null | awk '
                NR > 2 && $6 != "ESTABLISHED" && $6 != "LISTEN" {
                    print $1"|"$6"|"$4"|"$5"|"$7
                }'
            fi

        done | while IFS='|' read -r proto state src dst proc; do
            NOW=$(date +%s)
            entry="${proto}|${state}|${src}|${dst}|${proc}"
            echo "[$(ts)] $entry" >> "$LOG_CONNS"

            # Track outbound SYN_SENT as beacon candidates
            if [[ "$state" == "SYN-SENT" || "$state" == "SYN_SENT" ]]; then
                key="$dst"

                if [[ -z "${CONN_FIRST_SEEN[$key]:-}" ]]; then
                    CONN_FIRST_SEEN[$key]=$NOW
                    CONN_COUNTS[$key]=1
                else
                    CONN_COUNTS[$key]=$(( ${CONN_COUNTS[$key]:-0} + 1 ))
                fi
                CONN_LAST_SEEN[$key]=$NOW
                CONN_PROC[$key]="$proc"

                count=${CONN_COUNTS[$key]:-0}
                window_start=${CONN_FIRST_SEEN[$key]:-$NOW}
                elapsed=$(( NOW - window_start ))

                # Expire old entries
                if [[ $elapsed -gt $BEACON_WINDOW ]]; then
                    unset CONN_COUNTS[$key]
                    unset CONN_FIRST_SEEN[$key]
                    unset CONN_LAST_SEEN[$key]
                    unset CONN_PROC[$key]
                    continue
                fi

                if [[ $count -ge $BEACON_THRESHOLD ]]; then
                    interval=$(( elapsed / count ))

                    # Resolve executable path from PID via /proc/<pid>/exe
                    saved_proc="${CONN_PROC[$key]:-$proc}"
                    pid=$(echo "$saved_proc" | grep -oP 'pid=\K[0-9]+' | head -1)
                    if [[ -n "$pid" ]]; then
                        exe_path=$(readlink -f "/proc/$pid/exe" 2>/dev/null || echo "unknown")
                        proc_name=$(echo "$saved_proc" | grep -oP '"\K[^"]+' | head -1)
                        proc_info="pid=$pid name=$proc_name exe=$exe_path"
                    else
                        # netstat format: pid/name
                        proc_info="proc=$saved_proc"
                    fi

                    alert "BEACON DETECTED: $src -> $dst | $count connections in ${elapsed}s (~${interval}s interval) | $proc_info"
                    # Reset so we don't spam
                    unset CONN_COUNTS[$key]
                    unset CONN_FIRST_SEEN[$key]
                    unset CONN_PROC[$key]
                fi
            fi

            $VERBOSE && [[ "$state" != "TIME-WAIT" ]] && \
                echo "[CONN] $(ts) $proto $state $src -> $dst $proc"

        done

    ) &

    CHILD_PIDS+=($!)
    log INFO "Connection monitor PID: $!"
}

# ---------------------------------------------------------------------------- #
# 6. Full Packet Capture (pcap) for forensic analysis
#    Rotates every 10 minutes, keeps last 6 files
# ---------------------------------------------------------------------------- #
start_pcap_capture() {
    log INFO "Starting pcap capture (rotating) -> $OUTPUT_DIR/pcap/"

    if $HAS_TSHARK; then
        tshark -i "$IFACE" \
            -w "$OUTPUT_DIR/pcap/capture.pcap" \
            -b duration:600 \
            -b files:6 \
            2>/dev/null &
    elif $HAS_TCPDUMP; then
        tcpdump -i "$IFACE" \
            -w "$OUTPUT_DIR/pcap/capture.pcap" \
            -G 600 \
            -W 6 \
            2>/dev/null &
    fi

    CHILD_PIDS+=($!)
    log INFO "Pcap capture PID: $!"
}

# ---------------------------------------------------------------------------- #
# 7. Periodic Summary Reporter
#    Every 60s: prints counts of events detected
# ---------------------------------------------------------------------------- #
start_summary_reporter() {
    (
        while true; do
            sleep 60
            dns_count=$(wc -l < "$LOG_DNS" 2>/dev/null || echo 0)
            http_count=$(wc -l < "$LOG_HTTP" 2>/dev/null || echo 0)
            https_count=$(wc -l < "$LOG_HTTPS" 2>/dev/null || echo 0)
            beacon_count=$(wc -l < "$LOG_BEACONS" 2>/dev/null || echo 0)
            alert_count=$(grep -c '\[ALERT\]' "$LOG_SUMMARY" 2>/dev/null || echo 0)

            summary="[SUMMARY] DNS:${dns_count} HTTP:${http_count} TLS:${https_count} BEACONS:${beacon_count} ALERTS:${alert_count}"
            log INFO "$summary"
            echo "$summary"
        done
    ) &
    CHILD_PIDS+=($!)
}

# ---------------------------------------------------------------------------- #
# 8. /proc/net watcher — catches raw socket connections tshark might miss
# ---------------------------------------------------------------------------- #
start_proc_net_monitor() {
    (
        declare -A SEEN_CONNS
        while true; do
            # /proc/net/tcp has hex src:port -> dst:port, state
            # State 02 = SYN_SENT, 06 = TIME_WAIT, 08 = CLOSE_WAIT
            while IFS= read -r line; do
                state=$(echo "$line" | awk '{print $4}')
                if [[ "$state" == "02" || "$state" == "06" || "$state" == "08" ]]; then
                    local_hex=$(echo "$line" | awk '{print $2}')
                    remote_hex=$(echo "$line" | awk '{print $3}')

                    # Convert hex IP:port to dotted notation
                    decode_addr() {
                        local hex="$1"
                        local ip_hex="${hex%:*}"
                        local port_hex="${hex#*:}"
                        # Reverse byte order for little-endian
                        local ip
                        ip=$(printf "%d.%d.%d.%d" \
                            "0x${ip_hex:6:2}" \
                            "0x${ip_hex:4:2}" \
                            "0x${ip_hex:2:2}" \
                            "0x${ip_hex:0:2}")
                        local port
                        port=$(( 16#$port_hex ))
                        echo "${ip}:${port}"
                    }

                    remote=$(decode_addr "$remote_hex")
                    key="${state}_${remote}"

                    if [[ -z "${SEEN_CONNS[$key]:-}" ]]; then
                        SEEN_CONNS[$key]=1
                        state_name="UNKNOWN"
                        case "$state" in
                            02) state_name="SYN_SENT" ;;
                            06) state_name="TIME_WAIT" ;;
                            08) state_name="CLOSE_WAIT" ;;
                        esac
                        echo "[$(ts)] /proc/net|${state_name}|->|${remote}|" >> "$LOG_CONNS"
                        $VERBOSE && echo "[PROC] $state_name -> $remote"
                    fi
                fi
            done < <(awk 'NR>1' /proc/net/tcp 2>/dev/null)

            sleep "$POLL_INTERVAL"
        done
    ) &
    CHILD_PIDS+=($!)
}

# ---------------------------------------------------------------------------- #
# MAIN — Start all monitors
# ---------------------------------------------------------------------------- #
echo "[*] Starting monitors on interface: $IFACE"
echo "[*] Press Ctrl+C to stop and view summary"
echo ""

start_dns_monitor
start_http_monitor
start_https_monitor
start_c2port_monitor
start_connection_monitor
start_pcap_capture
start_summary_reporter

# Only run /proc/net monitor on Linux
if [[ -f /proc/net/tcp ]]; then
    start_proc_net_monitor
fi

echo ""
echo "[*] All monitors active. PIDs: ${CHILD_PIDS[*]}"
echo "[*] Logs:"
echo "    DNS:         $LOG_DNS"
echo "    HTTP:        $LOG_HTTP"
echo "    HTTPS/TLS:   $LOG_HTTPS"
echo "    Port traffic: $LOG_C2"
echo "    Connections: $LOG_CONNS"
echo "    Beacons:     $LOG_BEACONS"
echo "    Summary:     $LOG_SUMMARY"
[[ -n "$ALERT_FILE" ]] && echo "    Alert file:  $ALERT_FILE"
echo "    Pcap:        $OUTPUT_DIR/pcap/"
echo ""

# Wait for Ctrl+C
wait
