#!/usr/bin/env python3
"""hello/main.py — a simple script with 3 input fields for testing."""
import argparse
import sys


def main():
    parser = argparse.ArgumentParser(description="PyShell hello example")
    parser.add_argument("--name", type=str, default="World", help="Name to greet")
    parser.add_argument("--count", type=int, default=1, help="Number of greetings")
    parser.add_argument("--uppercase", action="store_true", help="Uppercase output")
    args = parser.parse_args()

    greeting = f"Hello, {args.name}!"
    if args.uppercase:
        greeting = greeting.upper()

    for i in range(args.count):
        print(f"[{i+1}/{args.count}] {greeting}", flush=True)

    print("Done!", flush=True)
    sys.exit(0)


if __name__ == "__main__":
    main()
