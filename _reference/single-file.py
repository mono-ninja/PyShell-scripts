#!/usr/bin/env python3
# /// script
# [tool.pyshell]
# id = "com.pyshell.example.single-file"
# name = "Single File Example"
# description = "A PEP 723 inline manifest example"
# python = ">=3.11"
#
# [[tool.pyshell.inputs]]
# key = "url"
# type = "url"
# label = "URL"
# required = true
# [tool.pyshell.inputs.binding]
# kind = "arg"
# flag = "--url"
# style = "space"
#
# [[tool.pyshell.inputs]]
# key = "timeout"
# type = "int"
# label = "Timeout (seconds)"
# default = 30
# min = 1
# max = 300
# [tool.pyshell.inputs.binding]
# kind = "arg"
# flag = "--timeout"
# style = "space"
# ///
"""single-file.py — PEP 723 inline manifest example."""
import argparse
import sys


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--url", type=str, required=True)
    parser.add_argument("--timeout", type=int, default=30)
    args = parser.parse_args()

    print(f"URL: {args.url}", flush=True)
    print(f"Timeout: {args.timeout}s", flush=True)
    print("Done!", flush=True)


if __name__ == "__main__":
    main()
