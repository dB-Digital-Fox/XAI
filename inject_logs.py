#!/usr/bin/env python3
"""
Wazuh Test Log Injector — via logger (syslog socket)
=====================================================
Sends logs through the system logger daemon via the `logger` command,
so they appear immediately in:
  - journald  (Wazuh monitors via <log_format>journald</log_format>)
  - /var/log/syslog  (Wazuh monitors via localfile)
  - OpenSearch Discover under wazuh-alerts-*

Usage:
  python3 inject_logs.py                  # all 38 logs, 0.8s apart
  python3 inject_logs.py --delay 2        # slower, easier to watch live
  python3 inject_logs.py --dry-run        # print commands, don't run them
  python3 inject_logs.py --category ssh   # only SSH logs
  python3 inject_logs.py --category forti # only FortiGate logs
  python3 inject_logs.py --watch          # tail alerts after injection

Categories: ssh, sudo, pam, systemd, kernel, web, dpkg, forti, vpn, xai
"""

import argparse
import subprocess
import sys
import time
from datetime import datetime

LOGS = [
    # ── XAI trigger — batch start ────────────────────────────────────────
    {
        "category": "xai",
        "facility": "local0.info",
        "tag": "xai-test",
        "msg": "XAI_TEST_TRIGGER batch-start seq=1"
    },

    # ── SSH brute force ───────────────────────────────────────────────────
    {
        "category": "ssh",
        "facility": "authpriv.warning",
        "tag": "sshd",
        "msg": "Failed password for root from 203.0.113.42 port 51234 ssh2"
    },
    {
        "category": "ssh",
        "facility": "authpriv.warning",
        "tag": "sshd",
        "msg": "Failed password for root from 203.0.113.42 port 51235 ssh2"
    },
    {
        "category": "ssh",
        "facility": "authpriv.warning",
        "tag": "sshd",
        "msg": "Failed password for root from 203.0.113.42 port 51236 ssh2"
    },
    {
        "category": "ssh",
        "facility": "authpriv.warning",
        "tag": "sshd",
        "msg": "Failed password for admin from 198.51.100.7 port 44001 ssh2"
    },
    {
        "category": "ssh",
        "facility": "authpriv.notice",
        "tag": "sshd",
        "msg": "Invalid user deploy from 198.51.100.7 port 44002 ssh2"
    },
    {
        "category": "ssh",
        "facility": "authpriv.info",
        "tag": "sshd",
        "msg": "Accepted publickey for devops from 192.168.1.15 port 22 ssh2: RSA SHA256:abc123"
    },
    {
        "category": "ssh",
        "facility": "authpriv.info",
        "tag": "sshd",
        "msg": "Disconnected from authenticating user root 203.0.113.42 port 51237 [preauth]"
    },

    # ── Sudo / privilege escalation ───────────────────────────────────────
    {
        "category": "sudo",
        "facility": "authpriv.notice",
        "tag": "sudo",
        "msg": "alice : TTY=pts/1 ; PWD=/home/alice ; USER=root ; COMMAND=/usr/bin/passwd"
    },
    {
        "category": "sudo",
        "facility": "authpriv.warning",
        "tag": "sudo",
        "msg": "www-data : command not allowed ; TTY=pts/2 ; PWD=/var/www ; USER=root ; COMMAND=/bin/bash"
    },
    {
        "category": "sudo",
        "facility": "authpriv.warning",
        "tag": "sudo",
        "msg": "bob : TTY=pts/3 ; PWD=/home/bob ; USER=root ; COMMAND=/usr/bin/apt install netcat"
    },

    # ── PAM ───────────────────────────────────────────────────────────────
    {
        "category": "pam",
        "facility": "authpriv.warning",
        "tag": "sshd",
        "msg": "pam_unix(sshd:auth): authentication failure; logname= uid=0 euid=0 tty=ssh ruser= rhost=10.0.0.9 user=root"
    },
    {
        "category": "pam",
        "facility": "authpriv.info",
        "tag": "sshd",
        "msg": "pam_unix(sshd:session): session opened for user devops by (uid=0)"
    },
    {
        "category": "pam",
        "facility": "authpriv.info",
        "tag": "sshd",
        "msg": "pam_unix(sshd:session): session closed for user devops"
    },

    # ── Systemd service events ────────────────────────────────────────────
    {
        "category": "systemd",
        "facility": "daemon.err",
        "tag": "systemd",
        "msg": "nginx.service: Main process exited, code=killed, status=9/KILL"
    },
    {
        "category": "systemd",
        "facility": "daemon.err",
        "tag": "systemd",
        "msg": "Failed to start PostgreSQL Database Server."
    },
    {
        "category": "systemd",
        "facility": "daemon.warning",
        "tag": "systemd",
        "msg": "cron.service: Scheduled restart job, restart counter is at 5."
    },
    {
        "category": "systemd",
        "facility": "daemon.info",
        "tag": "systemd",
        "msg": "Started OpenSSH server daemon."
    },

    # ── Kernel / firewall ─────────────────────────────────────────────────
    {
        "category": "kernel",
        "facility": "kern.warning",
        "tag": "kernel",
        "msg": "[UFW BLOCK] IN=eth0 OUT= SRC=203.0.113.100 DST=192.168.1.1 LEN=44 PROTO=TCP SPT=55423 DPT=23 WINDOW=512 SYN URGP=0"
    },
    {
        "category": "kernel",
        "facility": "kern.warning",
        "tag": "kernel",
        "msg": "[UFW BLOCK] IN=eth0 OUT= SRC=10.10.0.99 DST=192.168.1.1 LEN=28 PROTO=UDP SPT=5353 DPT=161 LEN=8"
    },
    {
        "category": "kernel",
        "facility": "kern.info",
        "tag": "kernel",
        "msg": "[UFW ALLOW] IN=eth0 OUT= SRC=192.168.1.50 DST=192.168.1.1 PROTO=TCP DPT=443"
    },

    # ── Web server ────────────────────────────────────────────────────────
    {
        "category": "web",
        "facility": "local7.warning",
        "tag": "nginx",
        "msg": f'203.0.113.55 - - [{datetime.now().strftime("%d/%b/%Y:%H:%M:%S +0000")}] "GET /wp-admin/install.php HTTP/1.1" 404 162 "-" "sqlmap/1.7.8"'
    },
    {
        "category": "web",
        "facility": "local7.warning",
        "tag": "nginx",
        "msg": f'10.0.0.2 - - [{datetime.now().strftime("%d/%b/%Y:%H:%M:%S +0000")}] "POST /api/v1/login HTTP/1.1" 401 89 "-" "python-requests/2.28"'
    },
    {
        "category": "web",
        "facility": "local7.err",
        "tag": "nginx",
        "msg": f'185.220.101.1 - - [{datetime.now().strftime("%d/%b/%Y:%H:%M:%S +0000")}] "GET /../../../etc/passwd HTTP/1.1" 400 0 "-" "curl/7.88"'
    },

    # ── dpkg / package changes ────────────────────────────────────────────
    {
        "category": "dpkg",
        "facility": "local4.info",
        "tag": "dpkg",
        "msg": "status installed nmap:amd64 7.93+dfsg1-1"
    },
    {
        "category": "dpkg",
        "facility": "local4.info",
        "tag": "dpkg",
        "msg": "status installed netcat-openbsd:amd64 1.219-1"
    },

    # ── FortiGate auth ────────────────────────────────────────────────────
    {
        "category": "forti",
        "facility": "local0.warning",
        "tag": "fortigate",
        "msg": f'date={datetime.now().strftime("%Y-%m-%d")} time={datetime.now().strftime("%H:%M:%S")} devname=FGT-LAB devid=FG200F logid=0100026001 type=event subtype=system level=warning msg="Admin login failed" user=admin ui=ssh srcip=192.168.10.5 reason=bad_password'
    },
    {
        "category": "forti",
        "facility": "local0.warning",
        "tag": "fortigate",
        "msg": f'date={datetime.now().strftime("%Y-%m-%d")} time={datetime.now().strftime("%H:%M:%S")} devname=FGT-LAB devid=FG200F logid=0100026001 type=event subtype=system level=warning msg="Admin login failed" user=root ui=https srcip=203.0.113.9 reason=bad_password'
    },
    {
        "category": "forti",
        "facility": "local0.info",
        "tag": "fortigate",
        "msg": f'date={datetime.now().strftime("%Y-%m-%d")} time={datetime.now().strftime("%H:%M:%S")} devname=FGT-LAB devid=FG200F logid=0100026000 type=event subtype=system level=information msg="Admin login successful" user=admin ui=ssh srcip=192.168.1.1'
    },

    # ── FortiGate traffic blocks ──────────────────────────────────────────
    {
        "category": "forti",
        "facility": "local0.warning",
        "tag": "fortigate",
        "msg": f'date={datetime.now().strftime("%Y-%m-%d")} time={datetime.now().strftime("%H:%M:%S")} devname=FGT-LAB devid=FG200F logid=0100032001 type=traffic subtype=forward level=warning action=deny srcip=10.0.0.99 dstip=8.8.8.8 proto=6 dstport=4444 service=UNKNOWN msg="Policy violation - suspicious outbound"'
    },
    {
        "category": "forti",
        "facility": "local0.warning",
        "tag": "fortigate",
        "msg": f'date={datetime.now().strftime("%Y-%m-%d")} time={datetime.now().strftime("%H:%M:%S")} devname=FGT-LAB devid=FG200F logid=0100032001 type=traffic subtype=forward level=warning action=deny srcip=10.0.0.55 dstip=185.220.101.33 proto=6 dstport=9001 service=UNKNOWN msg="Tor exit node detected"'
    },

    # ── FortiGate IPS ─────────────────────────────────────────────────────
    {
        "category": "forti",
        "facility": "local0.alert",
        "tag": "fortigate",
        "msg": f'date={datetime.now().strftime("%Y-%m-%d")} time={datetime.now().strftime("%H:%M:%S")} devname=FGT-LAB devid=FG200F logid=0900032101 type=utm subtype=ips level=alert action=dropped srcip=203.0.113.1 dstip=192.168.1.10 attack=CVE-2021-44228 severity=critical msg="Log4Shell exploit attempt detected and blocked"'
    },
    {
        "category": "forti",
        "facility": "local0.alert",
        "tag": "fortigate",
        "msg": f'date={datetime.now().strftime("%Y-%m-%d")} time={datetime.now().strftime("%H:%M:%S")} devname=FGT-LAB devid=FG200F logid=0900032102 type=utm subtype=ips level=alert action=dropped srcip=198.51.100.5 dstip=192.168.1.20 attack=CVE-2023-44487 severity=high msg="HTTP2 Rapid Reset attack"'
    },
    {
        "category": "forti",
        "facility": "local0.warning",
        "tag": "fortigate",
        "msg": f'date={datetime.now().strftime("%Y-%m-%d")} time={datetime.now().strftime("%H:%M:%S")} devname=FGT-LAB devid=FG200F logid=0900032103 type=utm subtype=webfilter level=warning action=blocked srcip=10.0.0.22 dstip=185.220.101.50 dstport=443 service=HTTPS msg="Malicious URL blocked" url=malware-download.ru'
    },

    # ── FortiGate VPN ─────────────────────────────────────────────────────
    {
        "category": "vpn",
        "facility": "local0.info",
        "tag": "fortigate",
        "msg": f'date={datetime.now().strftime("%Y-%m-%d")} time={datetime.now().strftime("%H:%M:%S")} devname=FGT-LAB devid=FG200F logid=0101039949 type=event subtype=vpn level=information action=tunnel-up srcip=198.51.100.77 dstip=203.0.113.10 msg="SSL VPN tunnel established" user=jsmith'
    },
    {
        "category": "vpn",
        "facility": "local0.warning",
        "tag": "fortigate",
        "msg": f'date={datetime.now().strftime("%Y-%m-%d")} time={datetime.now().strftime("%H:%M:%S")} devname=FGT-LAB devid=FG200F logid=0101039949 type=event subtype=vpn level=warning action=tunnel-down srcip=198.51.100.77 msg="SSL VPN tunnel disconnected unexpectedly" user=jsmith reason=timeout'
    },

    # ── FortiGate config change ───────────────────────────────────────────
    {
        "category": "forti",
        "facility": "local0.notice",
        "tag": "fortigate",
        "msg": f'date={datetime.now().strftime("%Y-%m-%d")} time={datetime.now().strftime("%H:%M:%S")} devname=FGT-LAB devid=FG200F logid=0100044546 type=event subtype=system level=notice msg="Configuration changed" user=admin ui=ssh cfgpath=firewall/policy cfgattr=action cfgold=accept cfgnew=deny'
    },

    # ── XAI trigger — batch end ───────────────────────────────────────────
    {
        "category": "xai",
        "facility": "local0.info",
        "tag": "xai-test",
        "msg": "XAI_TEST_TRIGGER batch-end seq=38"
    },
]


CATEGORY_COLORS = {
    "xai":     "\033[95m",
    "ssh":     "\033[91m",
    "sudo":    "\033[93m",
    "pam":     "\033[33m",
    "systemd": "\033[94m",
    "kernel":  "\033[96m",
    "web":     "\033[92m",
    "dpkg":    "\033[37m",
    "forti":   "\033[35m",
    "vpn":     "\033[36m",
}
RESET = "\033[0m"
BOLD  = "\033[1m"


def check_logger():
    result = subprocess.run(["which", "logger"], capture_output=True)
    if result.returncode != 0:
        print("✗  'logger' not found. Install with: sudo apt install bsdutils")
        sys.exit(1)


def send_log(entry, dry_run=False):
    # -- is required to stop logger treating message content as flags
    cmd = ["logger", "-p", entry["facility"], "-t", entry["tag"], "--", entry["msg"]]

    color = CATEGORY_COLORS.get(entry["category"], "")
    tag_str   = f"{BOLD}[{entry['category'].upper():8s}]{RESET}"
    facil_str = f"\033[2m{entry['facility']:22s}{RESET}"
    msg_preview = entry["msg"][:85] + ("…" if len(entry["msg"]) > 85 else "")

    print(f"  {tag_str} {color}{facil_str}  {msg_preview}{RESET}")

    if dry_run:
        print(f"           \033[2mcmd: {' '.join(cmd[:5])} …{RESET}")
        return True

    result = subprocess.run(cmd, capture_output=True, text=True)
    if result.returncode != 0:
        print(f"    {BOLD}\033[91m✗ logger error: {result.stderr.strip()}{RESET}")
        return False
    return True


def main():
    parser = argparse.ArgumentParser(
        description="Inject test logs into Wazuh via system logger",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="Categories: ssh, sudo, pam, systemd, kernel, web, dpkg, forti, vpn, xai"
    )
    parser.add_argument("--delay",    type=float, default=0.8,
                        help="Seconds between logs (default: 0.8)")
    parser.add_argument("--dry-run",  action="store_true",
                        help="Print logger commands without executing")
    parser.add_argument("--category", type=str, default=None,
                        help="Only inject logs of this category")
    parser.add_argument("--watch",    action="store_true",
                        help="Tail Wazuh alerts after injection")
    args = parser.parse_args()

    if not args.dry_run:
        check_logger()

    logs = LOGS
    if args.category:
        logs = [l for l in LOGS if l["category"] == args.category]
        if not logs:
            print(f"✗  No logs for category '{args.category}'")
            print(f"   Available: {', '.join(sorted(set(l['category'] for l in LOGS)))}")
            sys.exit(1)

    print(f"\n{BOLD}{'='*65}{RESET}")
    print(f"  {BOLD}Wazuh Log Injector{RESET}  —  {len(logs)} logs via logger")
    print(f"  Delay : {args.delay}s  |  Dry-run: {args.dry_run}")
    if args.category:
        print(f"  Filter: {args.category}")
    print(f"  Flow  : logger → /dev/log → rsyslog/journald → Wazuh → OpenSearch")
    print(f"{BOLD}{'='*65}{RESET}\n")

    sent = 0
    for i, entry in enumerate(logs, 1):
        print(f"{BOLD}[{i:02d}/{len(logs)}]{RESET}", end=" ")
        if send_log(entry, dry_run=args.dry_run):
            sent += 1
        if i < len(logs):
            time.sleep(args.delay)

    print(f"\n{BOLD}{'='*65}{RESET}")
    print(f"  {'✓' if not args.dry_run else '○'} {sent}/{len(logs)} logs {'sent' if not args.dry_run else 'previewed'}")
    print()
    print(f"  {BOLD}Verify in journald:{RESET}")
    print(f"    journalctl -f -t sshd -t sudo -t fortigate -t xai-test")
    print()
    print(f"  {BOLD}Verify in Wazuh alerts:{RESET}")
    print(f"    sudo tail -f /var/ossec/logs/alerts/alerts.json | python3 -m json.tool")
    print()
    print(f"  {BOLD}Verify XAI integration:{RESET}")
    print(f"    sudo tail -f /var/ossec/logs/integrations/custom-xai.log")
    print()
    print(f"  {BOLD}Verify syslog directly:{RESET}")
    print(f"    sudo grep -E 'xai-test|fortigate|XAI_TEST' /var/log/syslog | tail -20")
    print(f"{BOLD}{'='*65}{RESET}\n")

    if args.watch and not args.dry_run:
        print("Watching Wazuh alert stream (Ctrl+C to stop)...\n")
        subprocess.run([
            "sudo", "tail", "-f",
            "/var/ossec/logs/alerts/alerts.json",
            "/var/ossec/logs/integrations/custom-xai.log"
        ])


if __name__ == "__main__":
    main()