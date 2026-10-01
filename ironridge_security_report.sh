#!/usr/bin/env bash

# Ironridge daily security and login report for RHEL 10
# Run with: sudo ./ironridge_security_report.sh

set -uo pipefail
umask 077

DEFAULT_REPORT_DIR="/var/log/ironridge-security-reports"
SINCE="24 hours ago"
OUTPUT_FILE=""

usage() {
    cat <<'EOF'
Usage: sudo ./ironridge_security_report.sh [options]

Options:
  --since TIME    Journal time range accepted by journalctl.
                  Default: 24 hours ago
  --output FILE   Save the report to a specific file.
  -h, --help      Show this help message.

Examples:
  sudo ./ironridge_security_report.sh
  sudo ./ironridge_security_report.sh --since "today"
  sudo ./ironridge_security_report.sh --since "7 days ago" --output /root/weekly-security.txt
EOF
}

while (($# > 0)); do
    case "$1" in
        --since)
            if (($# < 2)); then
                echo "Error: --since requires a value." >&2
                exit 2
            fi
            SINCE="$2"
            shift 2
            ;;
        --output)
            if (($# < 2)); then
                echo "Error: --output requires a file path." >&2
                exit 2
            fi
            OUTPUT_FILE="$2"
            shift 2
            ;;
        -h|--help)
            usage
            exit 0
            ;;
        *)
            echo "Error: unknown option: $1" >&2
            usage >&2
            exit 2
            ;;
    esac
done

if ((EUID != 0)); then
    echo "Error: run this script with sudo so it can read security logs and account status." >&2
    exit 1
fi

if ! journalctl --since "$SINCE" -n 0 --no-pager >/dev/null 2>&1; then
    echo "Error: journalctl did not accept the time value: $SINCE" >&2
    exit 2
fi

timestamp="$(date '+%Y-%m-%d_%H%M%S')"
if [[ -z "$OUTPUT_FILE" ]]; then
    OUTPUT_FILE="${DEFAULT_REPORT_DIR}/security-report-${timestamp}.txt"
fi

output_dir="$(dirname -- "$OUTPUT_FILE")"
mkdir -p -- "$output_dir"
touch -- "$OUTPUT_FILE"
chmod 600 -- "$OUTPUT_FILE"

exec > >(tee -a "$OUTPUT_FILE") 2>&1

section() {
    printf '\n============================================================\n'
    printf '%s\n' "$1"
    printf '============================================================\n'
}

print_or_none() {
    local content="$1"
    if [[ -n "$content" ]]; then
        printf '%s\n' "$content"
    else
        printf 'No matching records found.\n'
    fi
}

command_status() {
    if command -v "$1" >/dev/null 2>&1; then
        return 0
    fi
    printf '%s is not installed on this system.\n' "$1"
    return 1
}

host_name="$(hostname -f 2>/dev/null || hostname)"
generated_at="$(date --iso-8601=seconds)"

printf 'IRONRIDGE DAILY SECURITY AND LOGIN REPORT\n'
printf 'Host: %s\n' "$host_name"
printf 'Generated: %s\n' "$generated_at"
printf 'Reporting period: since %s\n' "$SINCE"
printf 'Report file: %s\n' "$OUTPUT_FILE"

section "1 Successful SSH Logins"
successful_ssh="$({
    journalctl -u sshd --since "$SINCE" --no-pager -o short-iso 2>/dev/null || true
} | grep -E 'Accepted (password|publickey|keyboard-interactive)' || true)"
print_or_none "$successful_ssh"

section "2 Failed Authentication Attempts"
failed_auth="$({
    journalctl --since "$SINCE" --no-pager -o short-iso 2>/dev/null || true
} | grep -Ei 'Failed password|authentication failure|Invalid user|FAILED LOGIN|maximum authentication attempts exceeded' || true)"
print_or_none "$failed_auth"

section "3 Users Currently Signed In"
current_users="$(who -a 2>/dev/null || true)"
print_or_none "$current_users"

printf '\nCurrent session summary\n'
w -h 2>/dev/null || printf 'The w command could not read session data.\n'

section "4 Recent Sudo Activity"
sudo_activity="$({
    journalctl _COMM=sudo --since "$SINCE" --no-pager -o short-iso 2>/dev/null || true
    journalctl -t sudo --since "$SINCE" --no-pager -o short-iso 2>/dev/null || true
} | awk 'NF && !seen[$0]++' || true)"
print_or_none "$sudo_activity"

section "5 Locked Local Accounts"
uid_min="$(awk '$1 == "UID_MIN" {print $2; exit}' /etc/login.defs 2>/dev/null)"
uid_min="${uid_min:-1000}"
locked_output=""

while IFS=: read -r account _ uid _ _ _ shell; do
    if [[ "$uid" -ne 0 && "$uid" -lt "$uid_min" ]]; then
        continue
    fi
    if [[ "$shell" =~ (nologin|false)$ ]]; then
        continue
    fi

    status_line="$(passwd -S "$account" 2>/dev/null || true)"
    status_code="$(awk '{print $2}' <<<"$status_line")"
    if [[ "$status_code" == "L" || "$status_code" == "LK" ]]; then
        locked_output+="${status_line}"$'\n'
    fi
done < /etc/passwd

locked_output="${locked_output%$'\n'}"
print_or_none "$locked_output"
printf '\nNote: this section checks local accounts in /etc/passwd. Domain lockout status is managed in Active Directory.\n'

section "6 Firewall Status"
if command_status firewall-cmd; then
    printf 'firewalld service: %s\n' "$(systemctl is-active firewalld 2>/dev/null || true)"
    firewall-cmd --state 2>/dev/null || true

    printf '\nDefault zone\n'
    firewall-cmd --get-default-zone 2>/dev/null || true

    printf '\nActive zones\n'
    active_zones="$(firewall-cmd --get-active-zones 2>/dev/null || true)"
    print_or_none "$active_zones"

    zone_names="$(awk '/^[^[:space:]]/ {print $1}' <<<"$active_zones")"
    while IFS= read -r zone; do
        [[ -z "$zone" ]] && continue
        printf '\nConfiguration for active zone %s\n' "$zone"
        firewall-cmd --zone="$zone" --list-all 2>/dev/null || true
    done <<<"$zone_names"
else
    printf 'Firewall details were not collected.\n'
fi

section "7 SELinux Status"
if command_status getenforce; then
    printf 'Current mode: '
    getenforce
fi
if command_status sestatus; then
    sestatus
fi

section "8 Current Listening Ports"
if command_status ss; then
    listening_ports="$(ss -lntup 2>/dev/null || true)"
    print_or_none "$listening_ports"
else
    printf 'Listening ports were not collected.\n'
fi

section "9 Recent Firewall Change Events"
firewall_events="$({
    journalctl -u firewalld --since "$SINCE" --no-pager -o short-iso 2>/dev/null || true
} | grep -Ei 'port|service|zone|reload|configuration' || true)"
print_or_none "$firewall_events"
printf '\nNote: current listening ports are authoritative for the present state. Historical port changes appear only when firewalld or another audit source logged them.\n'

section "Report Complete"
printf 'Saved securely with mode 600 at %s\n' "$OUTPUT_FILE"

