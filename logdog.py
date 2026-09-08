#!/usr/bin/env python3
print(r"┌────────────────────────────────────────┐")
print(r"│   __                 _                 │")
print(r"│  / /  ___   __ _  __| | ___   __ _     │")
print(r"│ / /  / _ \ / _` |/ _` |/ _ \ / _` |    │")
print(r"│/ /__| (_) | (_| | (_| | (_) | (_| |    │")
print(r"│\____/\___/ \__, |\__,_|\___/ \__, |    │")
print(r"│            |___/             |___/     │")
print(r"│                                        │")
print(r"│         >> IP Log Analyzer <<          │")
print(r"└────────────────────────────────────────┘")

import sys
import re
from collections import Counter
import argparse
import subprocess

class LogDog:
    def __init__(self) -> None:
        self.ips_count: Counter = Counter()
        self.ip_regex = re.compile(r"\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}")
        self.time = re.compile(r"^\s*(\d{4}-\d{2}-\d{2}\s+\d{2}:\d{2}:\d{2}|\d{4}/\d{2}/\d{2}\s+\d{2}:\d{2}:\d{2}|\d{2}:\d{2}:\d{2}|\w+\s+\d{1,2}\s+\d{2}:\d{2}:\d{2})")
        self.wtmp_time = re.compile(r"\s*(\d{4}-\d{2}-\d{2}\s+\d{2}:\d{2}(:\d{2})?|\d{4}/\d{2}/\d{2}\s+\d{2}:\d{2}(:\d{2})?|\w+\s+\d{1,2}\s+\d{2}:\d{2}(:\d{2})?)")
        self.GREEN = "\033[92m"
        self.CYAN = "\033[96m"
        self.BOLD = "\033[1m"
        self.RESET = "\033[0m"
        self.RED = "\033[91m"
        self.BLUE = "\033[34m"
        self.login = re.compile(r"(Accepted|Successful) (\S+) for (\w+) from (\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})")
        # In `last` output the connected user is the first field of the line.
        self.wtmp_user = re.compile(r"^(\S+)\s+(?:pts/|tty)")

    def get_ips(self, filepath: str) -> None:
        print(f"\n{self.BOLD}{self.BLUE}=== GENERAL IP ACTIVITY ==={self.RESET}")
        with open(filepath, "r") as file:
            for line in file:
                found_ips = self.ip_regex.findall(line)
                if found_ips:
                    self.ips_count.update(found_ips)
            for ip, count in self.ips_count.most_common():
                print(f"[{self.GREEN}+{self.RESET}] {self.BOLD}IP:{self.RESET} {self.CYAN}{ip:>18}{self.RESET} appears{self.GREEN}{count:>4}{self.RESET} times")

    def get_successful_login(self, filepath: str) -> None:
        print(f"\n{self.BOLD}{self.BLUE}=== SUCCESSFUL LOGINS / COMPROMISES ==={self.RESET}")
        found = 0
        with open(filepath) as file:
            for line in file:
                match_log = self.login.search(line)
                if match_log:
                    match_time = self.time.search(line)
                    date = match_time.group(1).strip() if match_time else "Unknown Time"
                    found = 1
                    auth = match_log.group(2)
                    username = match_log.group(3)
                    ip = match_log.group(4)
                    print(f"[{self.GREEN}SUCCESS{self.RESET}] Account {self.BOLD}{username:<12}{self.RESET} by IP {self.CYAN}{ip:<15}{self.RESET} with authentication type {self.RED}{auth:<15}{self.RESET} at {date}")
            if found == 0:
                print("No successful login found.")

    def get_activated_shells(self, filepath: str) -> None:
        print(f"\n{self.BOLD}{self.BLUE}=== ACTIVATED TERMINALS ==={self.RESET}")
        # Detect if the file is already plain text (e.g. someone gave us
        # the output of `last` directly) vs a raw binary wtmp/utmp file.
        is_text = False
        try:
            with open(filepath, "rb") as f:
                sample = f.read(4096)
            sample.decode("utf-8")
            # crude heuristic: raw wtmp binaries are full of NUL bytes,
            # readable last-style dumps are not.
            if b"\x00" not in sample:
                is_text = True
        except (UnicodeDecodeError, OSError):
            is_text = False

        if is_text:
            with open(filepath, "r", encoding="utf-8", errors="replace") as file:
                lines = file.readlines()
        else:
            try:
                command = subprocess.run(["last", "-f", filepath], capture_output=True, text=True)
                lines = command.stdout.strip().splitlines()
            except Exception:
                with open(filepath, "rb") as file:
                    lines = file.read().decode("utf-8", errors="replace").splitlines()
        found = 0
        for line in lines:
            if "pts/" in line or "tty" in line:
                # Extract terminal identifier (pts/1, tty1, ttyS1, etc.)
                terminal_match = re.search(r'(pts/\d+|tty\d+|ttyS\d+|pts)(\d+)?', line)
                terminal = terminal_match.group(0) if terminal_match else "Unknown Terminal"

                # Extract the connected user (first field of a `last` line)
                user_match = self.wtmp_user.search(line)
                user = user_match.group(1) if user_match else "Unknown User"

                # Extract IP address
                found_ip = self.ip_regex.search(line)
                ip = found_ip.group(0) if found_ip else "Unknown IP"

                # Extract timestamp - capture both entry and exit times if available
                found_time = self.wtmp_time.search(line)
                time_str = found_time.group(1).strip() if found_time else "Unknown Time"

                found = 1
                print(f"[{self.RED}WTMP SESSION{self.RESET}] User: {self.GREEN}{user:<12}{self.RESET} | Terminal: {self.CYAN}{terminal:<10}{self.RESET} | IP: {self.CYAN}{ip:<15}{self.RESET} | Time: {time_str}")
        if found == 0:
            print("No terminal access found.") 


def main() -> None:
    parser = argparse.ArgumentParser(description="Log file analyzer")
    parser.add_argument("-l", "--log", help="path to .log file")
    parser.add_argument("-w", "--wtmp", help="path to wtmp file")
    args = parser.parse_args()
    log = LogDog()

    if args.log:
        log.get_ips(args.log)
        log.get_successful_login(args.log)
    if args.wtmp:
        log.get_activated_shells(args.wtmp)
    if not (args.wtmp or args.log):
        parser.print_help()

if __name__ == "__main__":
    main()
