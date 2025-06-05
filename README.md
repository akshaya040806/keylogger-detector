# 🔐 System-Based Keylogger Detector

This project is a Python-based tool to detect suspicious or malicious keylogging activity on a system. It scans source code, archives, and executables for patterns commonly found in keyloggers, using static analysis and integration with VirusTotal.

## 🧰 Features

- ✅ Detects suspicious keywords in Python scripts (`.py`, `.pyw`)
- ✅ Scans `.zip` and `.exe` files
- ✅ Integrates with VirusTotal API for EXE analysis
- ✅ HTML/JavaScript keylogger pattern detection
- ✅ Web interface using Flask

## 📂 How It Works

The tool performs:
- **Static code scanning** for known suspicious patterns (e.g., `pynput`, `keyboard`, `win32api`, `input()` hooks)
- **VirusTotal file hash lookup** (for EXEs)
- **Content decoding** for ZIP files
- **Local HTML analysis** for JS-based keyloggers

## 🚀 Getting Started

### Prerequisites

- Python 3.8+
- Install requirements:

```bash
pip install -r requirements.txt
