# Hextopsy - Static Malware Analysis Toolkit
# Copyright (c) 2026 5kidRo0t
#
# This program is free software: you can redistribute it and/or modify
# it under the terms of the GNU General Public License as published by
# the Free Software Foundation, either version 3 of the License, or
# (at your option) any later version.
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this program. If not, see <https://www.gnu.org/licenses/>.

import sys
import shutil
import subprocess
import tempfile
import time
import os
import signal
from pathlib import Path

TOOLS = {
    "binwalk": ["binwalk"],
    "pecheck": [
        "pecheck.py",
        "-d",
        "/var/lib/gems/2.5.0/gems/pedump-0.5.4/data/userdb.txt"
    ],
    "peframe": ["peframe"],
    "exiftool": ["exiftool"],
    "floss": ["floss"],
    "strings": ["strings"]
}

REPORTS = {
    "binwalk": "binwalk.txt",
    "pecheck": "pecheck.txt",
    "peframe": "peframe.txt",
    "exiftool": "exif.txt",
    "floss": "floss.txt",
    "strings": "strings.txt"
}

LIMITS = {
    "binwalk": {"timeout": 120, "max_output_mb": 15},
    "pecheck": {"timeout": 120, "max_output_mb": 15},
    "peframe": {"timeout": 180, "max_output_mb": 15},
    "exiftool": {"timeout": 60, "max_output_mb": 10},
    "floss": {"timeout": 180, "max_output_mb": 25},
    "strings": {"timeout": 60, "max_output_mb": 15}
}


def stop_process(process):

    try:
        if os.name == "posix":
            os.killpg(process.pid, signal.SIGTERM)
        else:
            process.terminate()

        process.wait(timeout=3)

    except subprocess.TimeoutExpired:

        if os.name == "posix":
            try:
                os.killpg(process.pid, signal.SIGKILL)
            except ProcessLookupError:
                pass
        else:
            process.kill()

        process.wait()

    except ProcessLookupError:
        pass
    
def generate_yara(sample, output_dir):

    yaragen = Path(__file__).resolve().parent / "modules" / "yaragen.py"

    if not yaragen.is_file():
        print("[!] YARA generator module not found.")
        return

    output_file = output_dir / f"{sample.stem}.yar"

    print("\n[*] Starting YARA rule generation...\n")

    try:
        result = subprocess.run(
            [
                sys.executable,
                str(yaragen),
                str(sample.resolve()),
                "-o",
                str(output_file)
            ],
            check=False
        )

        if result.returncode == 0:
            print("\n[+] YARA rule successfully generated.")

        else:
            print("\n[!] YARA rule generation failed.")

    except OSError as error:
        print(f"[!] Unable to execute YARA generator: {error}")

def main():

    if len(sys.argv) != 2:
        print("Usage: python3 hextopsy.py <file>")
        sys.exit(1)

    sample = Path(sys.argv[1])

    if not sample.is_file():
        print(f"[!] File not found: {sample}")
        sys.exit(1)

    def show_banner():

        banner = "@@@  @@@  @@@@@@@@  @@@  @@@  @@@@@@@   @@@@@@   @@@@@@@    @@@@@@   @@@ @@@\n@@@  @@@  @@@@@@@@  @@@  @@@  @@@@@@@  @@@@@@@@  @@@@@@@@  @@@@@@@   @@@ @@@\n@@!  @@@  @@!       @@!  !@@    @@!    @@!  @@@  @@!  @@@  !@@       @@! !@@\n!@!  @!@  !@!       !@!  @!!    !@!    !@!  @!@  !@!  @!@  !@!       !@! @!!\n@!@!@!@!  @!!!:!     !@@!@!     @!!    @!@  !@!  @!@@!@!   !!@@!!     !@!@!\n!!!@!!!!  !!!!!:      @!!!      !!!    !@!  !!!  !!@!!!     !!@!!!     @!!!\n!!:  !!!  !!:        !: :!!     !!:    !!:  !!!  !!:            !:!    !!:\n:!:  !:!  :!:       :!:  !:!    :!:    :!:  !:!  :!:           !:!     :!:\n::   :::   :: ::::   ::  :::     ::    ::::: ::   ::       :::: ::      ::\n :   : :  : :: ::    :   ::      :      : :  :    :        :: : :       :\n\n"
        print(banner)
        print("                 Hextopsy | Ver. 0.1")
        print("                    by 5kidRo0t")
        print("          Static Malware Analysis Toolkit")
        print("\n" + "=" * 58 + "\n")
    show_banner()
    print(f"\n[*] Analyzing: {sample.name}\n")

    print("[*] Select the directory where you want to save the reports.")
    print("[*] Example: /home/remnux/Documents/Analysis")
    print("[*] Press ENTER to use the current directory.\n")

    destination = input("Output directory: ").strip()

    if destination:
        output_dir = Path(destination).expanduser()
    else:
        output_dir = Path.cwd()

    try:
        output_dir.mkdir(parents=True, exist_ok=True)

        if not output_dir.is_dir():
            raise NotADirectoryError(output_dir)

    except OSError as error:
        print(f"[!] Unable to use directory: {error}")
        sys.exit(1)

    print(f"\n[+] Reports saved to: {output_dir.resolve()}\n")

    available = []
    unavailable = []
    results = {}

    for tool, command in TOOLS.items():

        if shutil.which(command[0]):
            available.append(tool)
        else:
            unavailable.append(tool)

    if not available:
        print("[!] No analysis tools are available.")
        sys.exit(1)

    for tool in available:

        output_file = output_dir / REPORTS[tool]

        timeout = LIMITS[tool]["timeout"]
        max_output = LIMITS[tool]["max_output_mb"] * 1024 * 1024

        print(f"[*] Running {tool}...")

        status = "COMPLETED"
        exit_code = None

        try:

            with tempfile.TemporaryFile() as stdout_tmp, \
                 tempfile.TemporaryFile() as stderr_tmp:

                process = subprocess.Popen(
                    TOOLS[tool] + [str(sample)],
                    stdout=stdout_tmp,
                    stderr=stderr_tmp,
                    start_new_session=(os.name == "posix")
                )

                start_time = time.monotonic()

                while process.poll() is None:

                    elapsed = time.monotonic() - start_time

                    output_size = (
                        os.fstat(stdout_tmp.fileno()).st_size +
                        os.fstat(stderr_tmp.fileno()).st_size
                    )

                    if elapsed > timeout:

                        status = "TIMEOUT"
                        stop_process(process)
                        break

                    if output_size > max_output:

                        status = "OUTPUT LIMIT"
                        stop_process(process)
                        break

                    time.sleep(0.25)

                exit_code = process.wait()

                if status == "COMPLETED":

                    output_size = (
                        os.fstat(stdout_tmp.fileno()).st_size +
                        os.fstat(stderr_tmp.fileno()).st_size
                    )

                    if output_size > max_output:
                        status = "OUTPUT LIMIT"

                stdout_tmp.seek(0)
                stderr_tmp.seek(0)

                stdout_data = stdout_tmp.read().decode(
                    "utf-8", errors="replace"
                )

                stderr_data = stderr_tmp.read().decode(
                    "utf-8", errors="replace"
                )

            if status == "COMPLETED" and exit_code != 0:
                status = "ERROR"

            with open(output_file, "w", encoding="utf-8") as report:

                report.write(stdout_data)

                if stderr_data:
                    report.write("\n\n--- STDERR ---\n")
                    report.write(stderr_data)

                report.write(f"\n\n--- STATUS: {status} ---\n")
                report.write(f"--- Exit code: {exit_code} ---\n")

            results[tool] = status

            if status == "COMPLETED":
                print(f"[+] Report generated: {output_file}")

            elif status == "ERROR":
                print(f"[!] {tool} finished with errors. Exit code: {exit_code}")
                print(f"[+] Report generated: {output_file}")

            else:
                print(f"[!] {tool} interrupted: {status}")
                print(f"[+] Partial results saved: {output_file}")

        except OSError as error:

            results[tool] = "ERROR"
            print(f"[!] Error executing {tool}: {error}")

    if unavailable:

        print("\n[!] Unavailable tools:")

        for tool in unavailable:
            print(f" - {tool}")
            
    generate_yara(sample, output_dir)
    print("\n========== HEXTOPSY SUMMARY ==========\n")

    for tool in TOOLS:

        if tool in results:
            print(f"[{results[tool]}] {tool}")

        elif tool in unavailable:
            print(f"[NOT FOUND] {tool}")

    print(f"\n[*] Reports available at: {output_dir.resolve()}")
    print("\n=======================================\n")
    print("[*] Process completed.")


if __name__ == "__main__":
    main()