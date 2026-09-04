#!/usr/bin/env python3
"""no-manifest.py — pure argparse, no manifest.

This script tests the introspection feature (M7): PyShell should
generate a form by monkey-patching argparse.parse_args.
"""
import argparse
import sys


def main():
    parser = argparse.ArgumentParser(description="Check links in a file")
    parser.add_argument("input_file", type=str, help="File to process")
    parser.add_argument("-o", "--output", type=str, default="output.txt", help="Output file")
    parser.add_argument("-v", "--verbose", action="store_true", help="Verbose output")
    parser.add_argument("-n", "--count", type=int, default=10, help="Number of items")
    parser.add_argument(
        "--mode",
        choices=["fast", "slow", "turbo"],
        default="fast",
        help="Processing mode",
    )
    args = parser.parse_args()

    print(f"Input: {args.input_file}", flush=True)
    print(f"Output: {args.output}", flush=True)
    print(f"Verbose: {args.verbose}", flush=True)
    print(f"Count: {args.count}", flush=True)
    print(f"Mode: {args.mode}", flush=True)
    print("Done!", flush=True)


if __name__ == "__main__":
    main()
