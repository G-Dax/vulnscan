# vulnscan

A small open-source desktop utility for checking files on your PC. This repository includes Guardian, a Python desktop app and command-line tool that scans files and completed downloads for suspicious indicators, and watches a selected folder for ransomware-like changes.

## Get the Windows app

After a push to `main`, GitHub Actions builds `Guardian.exe`. Open the repository's **Actions** tab, choose **Build Windows app**, then download the `Guardian-Windows` artifact from the completed workflow run. You can also build it locally on Windows by double-clicking `build_windows.bat` (Python 3 required).

## Run from source

Install Python 3.9 or newer with Tkinter available, then run:

```text
python guardian_ui.py
```

Open **Live protection**, select the folder your browser downloads to, and turn protection on. Guardian scans files after download activity settles. High-risk files are moved to its quarantine by default. See the **Quarantine** page to review or restore items.

For command-line use, run `python guardian.py --help`. Examples and options are also listed in the source file header.

## Detection limits

Guardian is an experimental, lightweight scanner. It does not use a comprehensive or automatically updated malware signature database and cannot detect every virus, trojan, ransomware sample, or other threat. A clean result does not prove a file is safe, and a finding can be a false positive. Keep Windows Defender or another maintained antivirus enabled and up to date. Quarantine moves a file; it does not disinfect it.

## License

MIT. See [LICENSE](LICENSE).

