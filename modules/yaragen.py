#!/usr/bin/env python3

import argparse
import hashlib
import re
import shutil
import subprocess
import sys
from pathlib import Path


CHUNK_SIZE = 1024 * 1024


def calculate_hashes(file_path):
    algorithms = {
        "md5": hashlib.md5(),
        "sha256": hashlib.sha256(),
        "sha512": hashlib.sha512()
    }

    with file_path.open("rb") as sample:
        while chunk := sample.read(CHUNK_SIZE):
            for digest in algorithms.values():
                digest.update(chunk)

    return {
        name: digest.hexdigest()
        for name, digest in algorithms.items()
    }


def ask_sample_name(filename):
    print(f"\n[+] Sample detected: {filename}")
    print("[?] Would you like to assign a custom name to this sample?")
    print("[?] Enter a name or press ENTER to use the original filename.")

    custom_name = input("[?] Malware name: ").strip()

    if custom_name:
        print(f"[+] Custom name assigned: {custom_name}")
        return custom_name

    print("[+] No custom name provided.")
    print("[+] Using original sample filename.")

    return Path(filename).stem


def yara_identifier(name):
    identifier = re.sub(
        r"[^A-Za-z0-9_]",
        "_",
        name
    )

    if not identifier:
        identifier = "sample"

    if identifier[0].isdigit():
        identifier = f"sample_{identifier}"

    return identifier


def yara_string(value):
    return value.replace("\\", "\\\\").replace('"', '\\"')


def build_rule(file_path, hashes, author, malware_name):
    file_size = file_path.stat().st_size
    rule_name = f"{yara_identifier(malware_name)}_malware"

    md5 = hashes["md5"]
    sha256 = hashes["sha256"]
    sha512 = hashes["sha512"]

    return f'''import "hash"

rule {rule_name}
{{
    meta:
        author = "{yara_string(author)}"
        description = "Exact malware sample identification"
        filename = "{yara_string(file_path.name)}"
        malware_name = "{yara_string(malware_name)}"
        md5 = "{md5}"
        sha256 = "{sha256}"
        sha512 = "{sha512}"

    condition:
        filesize == {file_size} and
        hash.sha256(0, filesize) == "{sha256}"
}}
'''


def validate_with_yara(rule_path, sample_path, expected_rule):
    yara = shutil.which("yara")

    if yara is None:
        print("[!] YARA executable not found. Validation skipped.")
        return False

    result = subprocess.run(
        [yara, str(rule_path), str(sample_path)],
        capture_output=True,
        text=True
    )

    if result.returncode != 0:
        print("[!] YARA validation failed:")
        print(result.stderr or result.stdout)
        return False

    matches = [
        line.split(maxsplit=1)[0]
        for line in result.stdout.splitlines()
        if line.strip()
    ]

    if expected_rule not in matches:
        print("[!] Rule compiled, but did not match the sample.")
        return False

    print(f"[+] Validation successful: {expected_rule}")
    return True


def main():

    parser = argparse.ArgumentParser(
        description="Generate exact-sample YARA rules."
    )

    parser.add_argument(
        "sample",
        help="Path to the malware sample."
    )

    parser.add_argument(
        "-o",
        "--output",
        help="Output YARA file."
    )

    parser.add_argument(
        "--author",
        default="5kidRo0t",
        help="Rule author."
    )

    args = parser.parse_args()

    sample_path = Path(args.sample).expanduser()

    if not sample_path.is_file():
        print("[!] Error: sample file does not exist.")
        return 1

    try:
        malware_name = ask_sample_name(sample_path.name)

        hashes = calculate_hashes(sample_path)

        output_path = (
            Path(args.output).expanduser()
            if args.output
            else sample_path.with_suffix(".yar")
        )

        rule = build_rule(
            sample_path,
            hashes,
            args.author,
            malware_name
        )

        output_path.write_text(rule, encoding="utf-8")

    except (OSError, EOFError) as error:
        print(f"[!] Error: {error}", file=sys.stderr)
        return 1

    print(f"\n[+] YARA rule generated: {output_path}")
    print(f"[+] Sample: {sample_path}")
    print(f"[+] Size: {sample_path.stat().st_size} bytes")
    print(f"[+] MD5: {hashes['md5']}")
    print(f"[+] SHA256: {hashes['sha256']}")
    print(f"[+] SHA512: {hashes['sha512']}")

    rule_name = f"{yara_identifier(malware_name)}_malware"

    if not validate_with_yara(
        output_path,
        sample_path,
        rule_name
    ):
        return 2

    return 0


if __name__ == "__main__":
    raise SystemExit(main())