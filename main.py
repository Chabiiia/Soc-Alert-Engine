import argparse
from soc_engine.rules_engine import detect_brute_force
from soc_engine.rules_engine import  detect_user_enumeration
from soc_engine.report import (print_header,print_brute_force_alerts,print_correlation_summary,print_summary,
                               print_user_enumeration_alerts)
from soc_engine.parser import parse_line


def parse_args():
    parser = argparse.ArgumentParser(description="SSH Auth Log Threat Detection Engine")
    parser.add_argument("log_file",help="Path to the log file to be analyzed")
    return parser.parse_args()

def main():
    args = parse_args()
    parsed_logs=[]

    try:
        with open(args.log_file, "r",encoding="utf-8") as file:
            for line in file:
                line=line.strip()
                if line:
                    parsed_entry=parse_line(line)
                    parsed_logs.append(parsed_entry)
    except FileNotFoundError:
        print(f"[X] Error: File '{args.log_file}' was not found.")
        return
    except Exception as e:
        print(f"[X] Unexpected error while reading file: {e}")
        return


    bf_alerts= detect_brute_force(
        parsed_logs,
    )
    enum_alerts=detect_user_enumeration(
        parsed_logs,
    )

    print_header(args.log_file, len(parsed_logs))
    print_user_enumeration_alerts(enum_alerts)
    print_brute_force_alerts(bf_alerts)
    print_correlation_summary(bf_alerts, enum_alerts)
    print_summary(bf_alerts, enum_alerts)


if __name__=="__main__":
    main()