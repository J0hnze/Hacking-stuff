#!/usr/bin/env python3

import csv
import json
import argparse
import sys


def get_headers(file):
    with open(file, newline='', encoding='utf-8') as f:
        reader = csv.reader(f)
        headers = next(reader)
    return headers


def extract_columns(file, columns):
    results = []

    with open(file, newline='', encoding='utf-8') as f:
        reader = csv.DictReader(f)

        for row in reader:
            filtered = {col: row[col] for col in columns if col in row}
            results.append(filtered)

    return results


def write_txt(data, columns, outfile):
    with open(outfile, "w") as f:
        for row in data:
            line = ",".join(row[col] for col in columns if col in row)
            f.write(line + "\n")


def write_json(data, outfile):
    with open(outfile, "w") as f:
        json.dump(data, f, indent=2)


def main():
    parser = argparse.ArgumentParser(description="Extract columns from CSV")
    parser.add_argument("-t", "--target", required=True, help="CSV file")
    parser.add_argument("-c", "--columns", nargs="+", help="Columns to extract")
    parser.add_argument("-o", "--output", required=True, help="Output file")
    parser.add_argument("-f", "--format", choices=["txt", "json"], default="txt")

    args = parser.parse_args()

    headers = get_headers(args.target)

    if not args.columns:
        print("Available headers:")
        for h in headers:
            print("-", h)
        sys.exit()

    data = extract_columns(args.target, args.columns)

    if args.format == "txt":
        write_txt(data, args.columns, args.output)
    else:
        write_json(data, args.output)


if __name__ == "__main__":
    main()
