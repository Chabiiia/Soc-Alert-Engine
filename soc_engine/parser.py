import re
from datetime import datetime

def parse_line(line: str) -> dict:
    ip_match = re.search(r"\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}", line)
    ip = ip_match.group() if ip_match else None

    if "Invalid user" in line:
        event_type = "invalid_user"
    elif "Failed password" in line:
        event_type = "failed_password"
    elif "Accepted password" in line:
        event_type = "accepted_password"
    elif "Connection closed" in line:
        event_type = "connection_closed"
    else : event_type="other"

    timestamp_match = re.search(r"^.{15}", line)
    if timestamp_match:
        try:
            timestamp = datetime.strptime(timestamp_match.group(),
            "%b %d %H:%M:%S").replace(year=datetime.now().year)
        except ValueError:
            timestamp = None
    else:
        timestamp = None

    pid_match = re.search(r"\[(\d+)\]",line)
    pid = pid_match.group(1) if pid_match else None

    return {
        "ip":ip,
        "event_type":event_type,
        "timestamp":timestamp,
        "pid":pid
    }
