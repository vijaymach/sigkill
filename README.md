# sigkill

> APK signature-check analysis / patch / resign / install pipeline.  
> Windows-friendly. No root required on the device.

---

## What It Does

`sigkill` is a command-line tool that automates the full workflow for locating, analyzing, and neutralizing Android APK signature self-verification checks — then rebuilding and re-signing the APK with your own certificate so it installs cleanly on a device.

```
doctor → init → cert → get → decode → analyze → patch → build → install
```

---

## Prerequisites

| Tool | Required For | Where to Get It |
|---|---|---|
| **Java 11+ (JDK)** | apktool, keytool | Android Studio JBR or [JDK 21](https://adoptium.net/) |
| **Android SDK Build-Tools** | zipalign, apksigner | Android Studio → SDK Manager |
| **ADB** | pull APKs, install | Android Studio → SDK Manager → Platform-Tools |
| **Python 3.8+** | running `.py` directly | [python.org](https://python.org) *(not needed for `.exe`)* |

> Set `ANDROID_HOME` or `ANDROID_SDK_ROOT` to your SDK root so the tool can auto-discover `build-tools` and `adb`.  
> Example: `C:\Users\you\AppData\Local\Android\Sdk`

---

## Installation

### Option A — Run as Python Script
```bash
# No extra pip dependencies — stdlib only
python sigkill.py doctor
```

### Option B — Run as Standalone EXE (Windows)
Built with PyInstaller from `sigkill.spec`:
```bash
pip install pyinstaller
pyinstaller sigkill.spec
# Output: dist\sigkill.exe
```
Copy `sigkill.exe` anywhere. All paths (`tools/`, `work/`, keystore, report) resolve relative to the `.exe`.

---

## Setup (One-Time)

### 1. Verify your toolchain
```bash
python sigkill.py doctor
```
```
  java           C:\Program Files\Android\Android Studio\jbr\bin\java.exe
  build-tools    C:\Users\you\AppData\Local\Android\Sdk\build-tools\34.0.0
  apksigner      ...\apksigner.bat
  zipalign       ...\zipalign.exe
  adb            ...\platform-tools\adb.exe
  apktool.jar    not downloaded
  keystore       not created
```

### 2. Download apktool
```bash
python sigkill.py init
```
Downloads the latest `apktool.jar` into `tools/`. Falls back to pinned `v2.11.1` if GitHub is unreachable.

### 3. Generate your signing keystore
```bash
python sigkill.py cert
```
Creates `release.keystore` (password: `android`) and writes your certificate SHA-256 fingerprint to `cert_sha256.txt`.

```
[+] keystore SHA-256 = a3f9e2b17c4d...
```

> Regenerate at any time with `--force`:
> ```bash
> python sigkill.py cert --force
> ```

---

## Commands

### `doctor` — Check toolchain
```bash
python sigkill.py doctor
```

### `init` — Download apktool
```bash
python sigkill.py init
```

### `cert` — Create signing keystore
```bash
python sigkill.py cert
python sigkill.py cert --force   # regenerate
```

### `get` — Pull APK from device
```bash
python sigkill.py get <package>
python sigkill.py get com.example.app
python sigkill.py get com.example.app -o my_output_dir
```
Connects via ADB, finds all APK splits, pulls them to `work/<package>/`.

### `decode` — Decompile APK to Smali
```bash
python sigkill.py decode <apk>
python sigkill.py decode work\com.example.app\base.apk
python sigkill.py decode work\com.example.app\base.apk -o decoded_app
python sigkill.py decode work\com.example.app\base.apk --force   # overwrite existing
```

### `analyze` — Scan for signature checks
```bash
python sigkill.py analyze <decoded_dir>
python sigkill.py analyze decoded_app
python sigkill.py analyze decoded_app --app-prefix com.example.app
python sigkill.py analyze decoded_app --top 50
```

Outputs a ranked list of candidates classified as:
- `ENFORCE` — app's own signature gate (high confidence)
- `sdk` — third-party ad/analytics SDK reads (noise, ignored)
- `noise` — unclassified, review manually

Full results written to `report.json`.

### `patch` — Neutralize signature checks
Two modes:

**`true` — stub check methods to always return `true` (1)**
```bash
python sigkill.py patch <dir> --mode true
python sigkill.py patch decoded_app --mode true --dry-run          # preview
python sigkill.py patch decoded_app --mode true                    # apply
python sigkill.py patch decoded_app --mode true --only-methods ".method public static checkSig(Landroid/content/Context;)Z"
```

**`hash` — replace hardcoded cert hashes with your keystore's hash**
```bash
python sigkill.py patch decoded_app --mode hash                    # uses cert_sha256.txt
python sigkill.py patch decoded_app --mode hash --hash a3f9e2b1...  # explicit hash
python sigkill.py patch decoded_app --mode hash --dry-run          # preview
```

### `build` — Recompile, align, and sign
```bash
python sigkill.py build <decoded_dir>
python sigkill.py build decoded_app
python sigkill.py build decoded_app -o my-patched.apk
```

Pipeline: `apktool b` → `zipalign -p -f 4` → `apksigner sign` → `apksigner verify`

### `install` — Push APK to device
```bash
python sigkill.py install <apk>
python sigkill.py install my-patched.apk
python sigkill.py install my-patched.apk --uninstall com.example.app
python sigkill.py install my-patched.apk --uninstall com.example.app --keep-data
```

### `run` — Auto-pipeline (pull → decode → analyze)
```bash
python sigkill.py run <package>
python sigkill.py run com.example.app
python sigkill.py run com.example.app --top 50
```

Chains `doctor → get → decode → analyze` automatically, then **stops before patching** so you can review `report.json`.

---

## Full Example — End to End

```bash
# One-time setup
python sigkill.py init
python sigkill.py cert

# Pull, decompile, and scan the app
python sigkill.py run com.example.app

# Review report.json, then pick a patch mode
python sigkill.py patch work\com.example.app\base --mode true --dry-run
python sigkill.py patch work\com.example.app\base --mode true

# Rebuild and sign
python sigkill.py build work\com.example.app\base -o patched.apk

# Install to connected device
python sigkill.py install patched.apk --uninstall com.example.app
```

---

## File & Directory Layout

```
sigkill.py          main script
sigkill.spec        PyInstaller build config
sigkill.exe         compiled standalone binary (after build)
release.keystore    generated signing key (created by 'cert')
cert_sha256.txt     your keystore SHA-256 fingerprint
report.json         analysis output from 'analyze'
tools/
  apktool.jar       downloaded by 'init'
work/
  <package>/
    split_00.apk    pulled base APK
    base.apk        alias for split_00
    base/           decoded smali + resources (apktool output)
```

---

## Analyze Scoring System

The analyzer ranks Smali methods using a heuristic score:

| Signal | Points |
|---|---|
| Each signature API token hit | +1 |
| Each "strong" token (`getSignatures`, `GET_SIGNING_CERTIFICATES`, etc.) | +1 extra |
| Conditional branch present (`if-eq`, `if-ne`, etc.) | +6 |
| Hardcoded hex hash literal (MD5/SHA-1/SHA-256 length) | +5 |
| Boolean or integer return type (`Z`, `I`) | +3 |
| Matches `--app-prefix` namespace | +4 |
| SDK/third-party namespace match | −12 |

Methods classified as `ENFORCE` are the primary patch targets.

---

## Patch Modes — When to Use Which

| Situation | Mode |
|---|---|
| `ENFORCE` methods found with boolean return (`ret=Z`) | `--mode true` |
| Hardcoded hash literals found in hex-literal report | `--mode hash` |
| Both found | Run `hash` first, then `true` |
| Neither found | Check native `.so` libs — not covered by this tool |

---

## Notes

- The keystore password is hardcoded as `android` — fine for personal use, change `KS_PASS` in source for anything sensitive.
- `--dry-run` on both patch modes previews changes without touching any files.
- Split APKs: `get` pulls all splits but `decode` only works on `base.apk`. Signature checks almost always live in the base.
- Native checks in `.so` files are out of scope for this tool.

---

## License

Do whatever you want with it.
