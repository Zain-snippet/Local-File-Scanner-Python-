# 🛡️ Python Folder Security Scanner

A lightweight local security scanner that analyzes files inside a folder, detects suspicious behavior, evaluates software versions against a vulnerability database, and produces detailed reports. It is designed to be **robust** (fails safely instead of crashing) and **practical for real-world use**.


## 🚀 What it does 

The scanner:

* scans a folder and all files inside it
* works through **CLI** (predefined path) and **GUI** (user selects folder at runtime)
* detects:

  * suspicious or malicious executables
  * dangerous scripts
  * obfuscation and payload indicators
* evaluates software versions using `vulnerabilities.json`
* generates reports
* shows real-time progress in the terminal
* **skips excluded folders automatically to prevent overload** (e.g., very large or noisy directories)

If anything critical is missing, it **does not crash** — it skips the failing part and completes the rest of the scan.


## 🔍 What it specifically checks for

The scanner applies multiple detection rules, including:

### 🧩 File-level suspicious indicators

* **double extensions** (e.g., `image.jpg.exe`)
* **mismatched file type vs extension**
* **modified `.exe` extensions**
* **files located in risky directories** (temp, startup, hidden system locations)
* **large file skip rule** (default: > 100 MB)

### 🧨 Malicious script behavior detection

It inspects file contents and flags patterns such as:

* deletion or wiping commands
* moving or copying sensitive data
* downloading remote payloads
* network beaconing / callbacks
* modifying system or hidden directories
* potential privilege abuse
* obfuscation indicators

### 🗂️ Executable & software analysis

Uses `vulnerabilities.json` to check:

* common software names (Chrome, VS Code, etc.)
* reported versions vs vulnerable versions
  *(database versions intentionally set high for testing)*
* software not listed in `vulnerabilities.json` is marked as **unknown** and treated as **potentially risky**

If the vulnerability DB is missing, software checks are skipped — file scanning still runs.


## 🖥️ CLI vs GUI behavior

| Mode    | Folder Selection               | Notes                      |
| ------- | ------------------------------ | -------------------------- |
| **CLI** | predefined path in config      | edit config before running |
| **GUI** | user selects folder at runtime | dynamic folder selection   |


## ⚙️ Required initial setup (important)

You must configure paths on your machine.

Update the following:

### ✅ 1) `config.json`

Set:

* `scan_path`
* `vulnerability_db_path`

`excluded_paths` helps **avoid overloading the scanner** by ignoring locations such as:

* system directories
* large tool caches
* folders with millions of tiny files

### ✅ 2) `module8_config_manager.py` → `get_default_config()`

Set default values for:

* `scan_path`
* `vulnerability_db_path`
* `excluded_paths` → list of directories that should be skipped during scanning

### ✅ 3) `main.py`

Set the path to `config.json`.

If paths are not valid, the scanner skips the relevant module instead of crashing.


## 🏃 How to run

Install dependencies:

```
pip install -r requirements.txt
```

Run CLI:

```
python main.py
```

Run GUI:

```
python gui_main.py
```


## 🛑 Built-in safety limits

To prevent overload:

* max file size: **100 MB** (skipped beyond this)
* concurrency limit: **4 workers**
* excluded paths are skipped entirely
* missing DB → software checks skipped safely


## 📊 Output & reports

During scanning the CLI displays:

* files discovered
* installed software detected
* vulnerability DB found / missing
* skipped items with reasons
* progress of scanning modules

Reports are saved in the **reports/** folder.


## 📁 Project structure

```
scanner/
 ├── *.py
 ├── tests/
 ├── reports/
 ├── config.json
 └── vulnerabilities.json
```


## ⚠️ Limitations

* vulnerability data from local JSON only
* Windows primarily supported
* conservative thresholds
* **Windows only** — not supported on macOS or Linux


## 🤝 Contributions

Issues and pull requests are welcome.

