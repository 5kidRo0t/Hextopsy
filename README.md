<img width="1336" height="824" alt="file_00000000b11081f4968144033d7af98a" src="https://github.com/user-attachments/assets/6c20118d-e2f0-49a3-bdd3-b2d5f1d322f9" />


### Static Malware Analysis Toolkit

**Developed by 5kidRo0t**  
**Version: 0.2**

![Python](https://img.shields.io/badge/Python-3.x-blue?logo=python)
![Platform](https://img.shields.io/badge/Platform-Linux-green?logo=linux)
![Version](https://img.shields.io/badge/Version-0.2-orange)
![Purpose](https://img.shields.io/badge/Purpose-Malware%20Analysis-red)

---

## 🔬 What is Hextopsy?

Hextopsy is a Python-based tool designed to automate the initial static information extraction process from suspicious files, particularly Windows PE executables.

Instead of manually executing several commands one by one, Hextopsy brings multiple analysis utilities together and collects their output into individual text reports.

Starting with version 0.2, Hextopsy also includes an integrated YARA rule generator that automatically creates and validates rules for identifying individual malware samples.

The objective is simple: **save time, organize information and make the initial malware triage process easier.**

Hextopsy does not attempt to replace the tools it uses. Instead, it acts as a lightweight wrapper that coordinates their execution and organizes their results.

## ⚙️ Version 0.2 — Features

Version 0.2 introduces an integrated YARA rule generation module while maintaining the automated information extraction functionality from the previous release.

Currently, Hextopsy supports the following tools:

| Tool | Purpose |
|---|---|
| Binwalk | Identifies embedded files, signatures and interesting data within a file. |
| PECheck | Extracts and checks information about Windows PE files. |
| PEframe | Performs static analysis of Windows PE executables. |
| ExifTool | Extracts metadata and file information. |
| FLOSS | Identifies and extracts obfuscated strings. |
| Strings | Extracts readable strings from binary files. |
| YARA Generator | Automatically generates and validates YARA rules for individual malware samples. |

### 📄 Automatic report generation

Each analysis utility generates its own `.txt` report:

```text
binwalk.txt
pecheck.txt
peframe.txt
exif.txt
floss.txt
strings.txt
```

The user can specify the directory where the reports will be stored.

If no directory is provided, Hextopsy automatically uses the current working directory.

### 🧬 Automatic YARA rule generation

Hextopsy includes an integrated module responsible for generating YARA rules automatically.

After the static information extraction process, the module:

- Calculates the sample's MD5, SHA256 and SHA512 hashes.
- Retrieves the sample's file size.
- Allows the user to assign a custom name to the sample.
- Uses the original filename if no custom name is provided.
- Generates a YARA rule designed to identify the exact sample.
- Stores the generated rule in the selected output directory.
- Automatically validates the generated rule against the original sample using YARA.

The generated rule uses the file size and SHA256 hash to identify the exact sample.

### ⏱️ Execution safeguards

Hextopsy includes basic execution safeguards:

- Individual execution timeouts for each tool.
- Maximum output limits to prevent excessive report generation.
- Process termination when a timeout or output limit is reached.
- Partial report preservation when an execution is interrupted.
- A final summary displaying the execution status of each utility.

Possible execution statuses:

- `COMPLETED`
- `ERROR`
- `TIMEOUT`
- `OUTPUT LIMIT`
- `NOT FOUND`

## 📦 Requirements

Hextopsy requires Python 3 and the external analysis utilities listed below.

To use the complete functionality, make sure all six analysis tools are installed and accessible through your system's PATH.

### Required tools

- Python 3
- Binwalk
- PECheck (`pecheck.py`)
- PEframe
- ExifTool
- FLOSS
- GNU Strings
- YARA

**Important:** PECheck requires its corresponding database file. The current version uses the following REMnux-specific path:

```text
/var/lib/gems/2.5.0/gems/pedump-0.5.4/data/userdb.txt
```

If your installation uses a different location, you may need to adjust the path in `hextopsy.py`.

YARA is required to validate the generated rules. If the YARA executable is unavailable, rule validation cannot be performed.

### Recommended environment

Hextopsy is currently intended for Linux environments, particularly malware-analysis distributions such as REMnux.

Some of the required utilities may already be included in your distribution.

If an analysis utility is missing, Hextopsy will report it as `NOT FOUND` and continue with the remaining available tools.

## 🚀 Usage

Clone the repository:

```bash
git clone https://github.com/5kidRo0t/Hextopsy.git
```

Enter the project directory:

```bash
cd Hextopsy
```

Run Hextopsy against a file:

```bash
python3 hextopsy.py malware.exe
```

Hextopsy will display its banner and begin the extraction process.

You will then be asked where you want to save the generated reports.

Example:

```text
[*] Select the directory where reports will be saved.
[*] Example: /home/remnux/Documents/Analysis
[*] Press ENTER to use the current directory.

Output directory:
```

Simply press ENTER to save the reports in the current working directory.

After the analysis reports have been generated, Hextopsy will start the YARA rule generation process and ask whether you want to assign a custom name to the sample.

## 📂 Example output

After processing a sample, the destination directory will contain:

```text
Analysis/
│
├── binwalk.txt
├── pecheck.txt
├── peframe.txt
├── exif.txt
├── floss.txt
├── strings.txt
└── malware.yar
```

Each report contains the output generated by its corresponding utility, along with execution status information.

The `.yar` file contains the automatically generated YARA rule for identifying the analyzed sample.

## 🛡️ Security considerations

Hextopsy is designed to perform initial static information extraction.

It does not intentionally execute the analyzed sample.

However, static analysis tools process potentially malicious or malformed files. For this reason, it is strongly recommended to use Hextopsy inside an isolated malware-analysis environment, preferably a dedicated virtual machine.

**Hextopsy is an information-gathering tool, not a complete malware analysis solution.**

The collected reports should be examined and interpreted by the analyst.

## 🧬 Future development

Hextopsy is an ongoing personal project.

Possible future improvements include:

- Additional static analysis utilities.
- Improved report organization.
- More flexible tool configuration.
- Additional file format support.
- More advanced automated information extraction.

These are potential development goals and are not necessarily implemented in the current release.

## 👨‍💻 Author

Developed by **5kidRo0t**.

Independent malware analysis enthusiast interested in reverse engineering, defensive security and malware research.

---

### ⚠️ Disclaimer

Hextopsy is intended for educational purposes, defensive security research and malware analysis.

The author is not responsible for misuse of this software.

**Analyze responsibly. Research ethically.**

---

*Hextopsy — Extracting information, one sample at a time.* 🦠
