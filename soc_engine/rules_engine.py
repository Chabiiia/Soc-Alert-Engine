from collections import defaultdict

def detect_brute_force(parsed_logs: list[dict],threshold: int=3,window_seconds: int=60)->list[dict]:
    failed_by_ip = defaultdict(list)
    for log in parsed_logs:
        if log["event_type"] == "failed_password":
            if log["ip"] and log["timestamp"]:
                failed_by_ip[log["ip"]].append(log["timestamp"])

    results = []

    for ip,timestamps in failed_by_ip.items():
            if len(timestamps) < threshold:
                continue

            timestamps = sorted(timestamps)
            for i in range(len(timestamps) - threshold +1):
                start_time = timestamps[i]
                end_time = timestamps[i + threshold - 1]

                time_diff = (end_time-start_time).total_seconds()

                if time_diff <= window_seconds:
                    results.append({
                    "ip": ip,
                    "failed_count": len(timestamps),
                    "first_failed": start_time,
                    "last_failed": end_time
                    })
                    break

    return results