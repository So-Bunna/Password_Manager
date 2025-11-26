#!/usr/bin/env python3
"""Password Manager - starter CLI


This is a minimal starter file for the project. Expand later.
"""


import argparse


VERSION = "0.1.0"




def main():
    parser = argparse.ArgumentParser(description="Password Manager (starter)")
    parser.add_argument("--version", action="store_true", help="show version")
    args = parser.parse_args()
    if args.version:
        print(f"Password Manager {VERSION}")
    else:
        print("Password Manager starter. Implement features in src/crypto and src/storage.")




if __name__ == "__main__":
    main()