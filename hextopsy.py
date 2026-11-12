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


def main():

    if len(sys.argv) != 2:
        print("Uso: python3 hextopsy.py <archivo>")
        sys.exit(1)

    sample = Path(sys.argv[1])

    if not sample.is_file():
        print(f"[!] Archivo no encontrado: {sample}")
        sys.exit(1)

    def show_banner():

        banner = "@@@  @@@  @@@@@@@@  @@@  @@@  @@@@@@@   @@@@@@   @@@@@@@    @@@@@@   @@@ @@@\n@@@  @@@  @@@@@@@@  @@@  @@@  @@@@@@@  @@@@@@@@  @@@@@@@@  @@@@@@@   @@@ @@@\n@@!  @@@  @@!       @@!  !@@    @@!    @@!  @@@  @@!  @@@  !@@       @@! !@@\n!@!  @!@  !@!       !@!  @!!    !@!    !@!  @!@  !@!  @!@  !@!       !@! @!!\n@!@!@!@!  @!!!:!     !@@!@!     @!!    @!@  !@!  @!@@!@!   !!@@!!     !@!@!\n!!!@!!!!  !!!!!:      @!!!      !!!    !@!  !!!  !!@!!!     !!@!!!     @!!!\n!!:  !!!  !!:        !: :!!     !!:    !!:  !!!  !!:            !:!    !!:\n:!:  !:!  :!:       :!:  !:!    :!:    :!:  !:!  :!:           !:!     :!:\n::   :::   :: ::::   ::  :::     ::    ::::: ::   ::       :::: ::      ::\n :   : :  : :: ::    :   ::      :      : :  :    :        :: : :       :\n\n"
        print(banner)
        print("                 Hextopsy | Ver. 0.1")
        print("                    by 5kidRo0t")
        print("          Static Malware Analysis Toolkit")
        print("\n" + "=" * 58 + "\n")
    show_banner()
    print(f"\n[*] Analizando: {sample.name}\n")

    print("[*] Selecciona el directorio donde guardar los informes.")
    print("[*] Ejemplo: /home/remnux/Documents/Analysis")
    print("[*] Pulsa ENTER para utilizar el directorio actual.\n")

    destination = input("Directorio de salida: ").strip()

    if destination:
        output_dir = Path(destination).expanduser()
    else:
        output_dir = Path.cwd()

    try:
        output_dir.mkdir(parents=True, exist_ok=True)

        if not output_dir.is_dir():
            raise NotADirectoryError(output_dir)

    except OSError as error:
        print(f"[!] No se puede utilizar el directorio: {error}")
        sys.exit(1)

    print(f"\n[+] Informes guardados en: {output_dir.resolve()}\n")

    available = []
    unavailable = []
    results = {}

    for tool, command in TOOLS.items():

        if shutil.which(command[0]):
            available.append(tool)
        else:
            unavailable.append(tool)

    if not available:
        print("[!] No hay ninguna herramienta disponible.")
        sys.exit(1)

    for tool in available:

        output_file = output_dir / REPORTS[tool]

        timeout = LIMITS[tool]["timeout"]
        max_output = LIMITS[tool]["max_output_mb"] * 1024 * 1024

        print(f"[*] Ejecutando {tool}...")

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
                print(f"[+] Informe generado: {output_file}")

            elif status == "ERROR":
                print(f"[!] {tool} terminó con errores. Exit code: {exit_code}")
                print(f"[+] Informe generado: {output_file}")

            else:
                print(f"[!] {tool} interrumpida: {status}")
                print(f"[+] Resultados parciales guardados: {output_file}")

        except OSError as error:

            results[tool] = "ERROR"
            print(f"[!] Error ejecutando {tool}: {error}")

    if unavailable:

        print("\n[!] Herramientas no disponibles:")

        for tool in unavailable:
            print(f" - {tool}")

    print("\n========== HEXTOPSY SUMMARY ==========\n")

    for tool in TOOLS:

        if tool in results:
            print(f"[{results[tool]}] {tool}")

        elif tool in unavailable:
            print(f"[NOT FOUND] {tool}")

    print(f"\n[*] Informes disponibles en: {output_dir.resolve()}")
    print("\n=======================================\n")
    print("[*] Proceso finalizado.")


if __name__ == "__main__":
    main()