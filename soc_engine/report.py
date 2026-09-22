RED = "\033[91m"
YELLOW = "\033[93m"
GREEN = "\033[92m"
CYAN = "\033[96m"
RESET = "\033[0m"
BOLD = "\033[1m"


def print_header(log_file: str, total_lines: int) -> None:
    print(f"\n{BOLD}=== SOC Alert Engine Report ==={RESET}")
    print(f"Log source: {log_file}")
    print(f"Total lines analyzed: {total_lines}\n")


def print_brute_force_alerts(alerts: list[dict]) -> None:
    print(f"{BOLD}{RED}[ALERT] Brute Force Detected{RESET}  (MITRE ATT&CK: T1110.001 - Password Guessing)")
    if not alerts:
        print("  No detected events.\n")
        return

    for a in sorted(alerts, key=lambda x: -x["failed_count"]):
        duration = (a["last_failed"] - a["first_failed"]).total_seconds()
        print(f"  {RED}IP: {a['ip']}{RESET}")
        print(f"    Failed attempts: {a['failed_count']}")
        print(f"    Window: {a['first_failed']} -> {a['last_failed']} ({duration:.0f}s)")
    print()


def print_user_enumeration_alerts(alerts: list[dict]) -> None:
    print(f"{BOLD}{YELLOW}[ALERT] User Enumeration Detected{RESET}  (MITRE ATT&CK: T1087.001 - Account Discovery)")
    if not alerts:
        print("  No detected events.\n")
        return

    for a in sorted(alerts, key=lambda x: -x["distinct_user_count"]):
        sample = ", ".join(a["usernames"][:6])
        more = f" (+{len(a['usernames']) - 6} more)" if len(a["usernames"]) > 6 else ""
        print(f"  {YELLOW}IP: {a['ip']}{RESET}")
        print(f"    Distinct usernames tried: {a['distinct_user_count']}")
        print(f"    Sample: {sample}{more}")
    print()


def print_correlation_summary(brute_force_alerts: list[dict], enumeration_alerts: list[dict]) -> None:
    bf_ips = {a["ip"] for a in brute_force_alerts}
    enum_ips = {a["ip"] for a in enumeration_alerts}
    overlap = bf_ips & enum_ips

    if not overlap:
        return

    print(f"{BOLD}{CYAN}[HIGH SEVERITY] Correlated Activity{RESET}")
    print("  The following IPs triggered BOTH brute force and user enumeration alerts,")
    print("  which may indicate an automated, multi-stage attack attempt:\n")
    for ip in overlap:
        print(f"  {CYAN}{ip}{RESET}")
    print()


def print_summary(brute_force_alerts: list[dict], enumeration_alerts: list[dict]) -> None:
    bf_ips = {a["ip"] for a in brute_force_alerts}
    enum_ips = {a["ip"] for a in enumeration_alerts}
    total_unique_ips = len(bf_ips | enum_ips)

    print(f"{BOLD}=== Summary ==={RESET}")
    print(f"  Brute force alerts: {len(brute_force_alerts)}")
    print(f"  User enumeration alerts: {len(enumeration_alerts)}")
    print(f"  Total unique suspicious IPs: {total_unique_ips}\n")