#!/usr/bin/env python3
"""
sigkill.py - APK signature-check analysis / patch / resign / install pipeline.

Windows-friendly. No root required on the device.

Commands:
    doctor                          verify toolchain
    init                            download apktool
    cert                            create keystore + print SHA-256
    get <package>                   adb pull the installed base/split APKs
    decode <apk> [-o dir]           apktool decode
    analyze <dir>                   scan smali, rank signature-check candidates
    patch <dir> --mode true|hash    apply patch
    build <dir> -o out.apk          apktool build + zipalign + apksigner
    install <apk> [--keep-data]     adb install
    run <package>                   doctor->get->decode->analyze (stops before patch)
"""

import argparse
import hashlib
import json
import os
import re
import shutil
import subprocess
import sys
import urllib.request
from pathlib import Path

if getattr(sys, "frozen", False):
    HERE = Path(sys.executable).resolve().parent       # exe mode: everything lives next to the binary
else:
    HERE = Path(__file__).resolve().parent
TOOLS = HERE / "tools"
WORK = HERE / "work"
APKTOOL_JAR = TOOLS / "apktool.jar"
KS = HERE / "release.keystore"
KS_PASS = "android"

APKTOOL_PINNED = "https://github.com/iBotPeaches/Apktool/releases/download/v2.11.1/apktool_2.11.1.jar"

# smali / java tokens that appear in signature self-checks
SIG_TOKENS = [
    "getPackageInfo",
    "getInstalledPackages",
    "getInstalledApplications",
    "GET_SIGNATURES",
    "GET_SIGNING_CERTIFICATES",
    "getSignatures",
    "getSigningInfo",
    "getApkContentsSigners",
    "Landroid/content/pm/Signature;",
    "getCertificateChain",
    "MessageDigest",
    "SHA-256",
    "SHA1",
    "MD5",
    "getPackageManager",
]

HEX_STR = re.compile(
    r'(const-string(?:/jumbo)?\s+[vp]\d+,\s*")([0-9a-fA-F]{32}|[0-9a-fA-F]{40}|[0-9a-fA-F]{64})(")'
)

# most signature reads are analytics/attribution, not self-protection.
# anything under these namespaces is noise for our purpose.
SDK_PREFIXES = [
    "com/unity3d", "com/google/android/gms", "com/google/firebase",
    "com/google/android/material", "com/fyber", "com/safedk", "com/applovin",
    "com/facebook", "com/adjust", "com/bytedance", "com/ironsource",
    "com/vungle", "com/adcolony", "com/mopub", "com/appsflyer",
    "com/crashlytics", "com/appboy", "com/braze", "com/onesignal",
    "io/branch", "com/mixpanel", "com/amplitude", "com/yandex",
    "com/appmetrica", "com/singular", "com/tencent", "com/huawei",
    "com/samsung", "com/tapjoy", "com/chartboost",
    "com/unity3d/services", "com/google/android/gms/measurement",
    # framework / second-tier ad + analytics stacks
    "androidx/", "com/pgl", "com/inmobi", "com/ogury", "com/google/ads",
    "com/google/android/ads", "com/mbridge", "com/mintegral", "com/unity",
    "com/hyprmx", "com/liftoff", "com/pangle", "com/smaato", "com/inmobi/ads",
    "com/cloudflare", "com/bugsnag", "com/sentry", "io/sentry",
    "com/kochava", "com/branch", "com/mparticle", "com/clevertap",
    "com/uxcam", "com/newrelic", "com/datadog", "com/segment",
]

COND_BRANCH = re.compile(r"^\s*if-(eq|ne|eqz|nez|lt|le|gt|ge)\b", re.M)

SIG_STRONG = {"getPackageInfo", "GET_SIGNATURES", "GET_SIGNING_CERTIFICATES",
              "getSignatures", "getSigningInfo", "getApkContentsSigners",
              "Landroid/content/pm/Signature;", "getCertificateChain"}

# never a self-signature gate: constructors, framework glue
NEVER_ENFORCE = ("constructor <init>", "constructor <clinit>")

METHOD_HDR = re.compile(r"^\.method\s+(.*)$")
END_METHOD = re.compile(r"^\.end method\b")


# ----------------------------------------------------------------- utils
def die(msg, code=1):
    print(f"[x] {msg}")
    sys.exit(code)


def info(msg):
    print(f"[*] {msg}")


def ok(msg):
    print(f"[+] {msg}")


def warn(msg):
    print(f"[!] {msg}")


def run(cmd, capture=True, check=True):
    if isinstance(cmd, (list, tuple)):
        args = [str(c) for c in cmd]
    else:
        args = cmd
    if capture:
        p = subprocess.run(args, capture_output=True, text=True, errors="replace")
        if check and p.returncode != 0:
            die(f"command failed ({p.returncode}): {' '.join(args)}\n{p.stdout}\n{p.stderr}")
        return p
    return subprocess.run(args).returncode


# ----------------------------------------------------------------- env
def find_java():
    cands = []
    jh = os.environ.get("JAVA_HOME")
    if jh:
        cands.append(Path(jh) / "bin" / ("java.exe" if os.name == "nt" else "java"))
    la = os.environ.get("LOCALAPPDATA")
    if la:
        cands.append(Path(la) / "Android" / "Sdk" / "jbr" / "bin" / "java.exe")
    cands += [
        Path(r"C:\Program Files\Android\Android Studio\jbr\bin\java.exe"),
        Path(r"C:\Program Files\Java\jdk-21\bin\java.exe"),
    ]
    for c in cands:
        if c.exists():
            return c
    w = shutil.which("java")
    return Path(w) if w else None


def find_build_tools():
    roots = []
    for k in ("ANDROID_HOME", "ANDROID_SDK_ROOT"):
        v = os.environ.get(k)
        if v:
            roots.append(Path(v))
    la = os.environ.get("LOCALAPPDATA")
    if la:
        roots.append(Path(la) / "Android" / "Sdk")
    roots.append(Path(r"C:\Android"))

    def ver_key(p):
        return [int(x) if x.isdigit() else 0 for x in p.name.split(".")]

    for r in roots:
        bt = r / "build-tools"
        if not bt.is_dir():
            continue
        vers = sorted([d for d in bt.iterdir() if d.is_dir()], key=ver_key, reverse=True)
        for v in vers:
            if (v / "apksigner.bat").exists() or (v / "apksigner").exists():
                return v
    return None


def find_adb():
    w = shutil.which("adb")
    if w:
        return Path(w)
    p = Path(r"C:\Android\platform-tools\adb.exe")
    return p if p.exists() else None


def tool(name, bt):
    """resolve a build-tools executable"""
    if not bt:
        die("Android build-tools not found. Set ANDROID_HOME or install SDK build-tools.")
    for suffix in (".bat", ".exe", ""):
        p = bt / f"{name}{suffix}"
        if p.exists():
            return p
    die(f"{name} not found in {bt}")


def ensure_apktool(java):
    if APKTOOL_JAR.exists() and APKTOOL_JAR.stat().st_size > 1_000_000:
        return APKTOOL_JAR
    TOOLS.mkdir(parents=True, exist_ok=True)
    url = APKTOOL_PINNED
    try:
        info("querying apktool latest release")
        req = urllib.request.Request(
            "https://api.github.com/repos/iBotPeaches/Apktool/releases/latest",
            headers={"User-Agent": "sigkill"},
        )
        with urllib.request.urlopen(req, timeout=20) as r:
            rel = json.load(r)
        for a in rel.get("assets", []):
            if a["name"].endswith(".jar"):
                url = a["browser_download_url"]
                break
    except Exception as e:
        warn(f"release query failed ({e}); using pinned {APKTOOL_PINNED}")

    info(f"downloading {url}")
    try:
        with urllib.request.urlopen(url, timeout=120) as r, open(APKTOOL_JAR, "wb") as f:
            shutil.copyfileobj(r, f)
    except Exception as e:
        die(f"apktool download failed: {e}")
    ok(f"apktool -> {APKTOOL_JAR}")
    return APKTOOL_JAR


def apktool(java, args):
    p = run([java, "-jar", str(APKTOOL_JAR)] + args, check=False)
    return p


# ----------------------------------------------------------------- commands
def cmd_doctor(a):
    java = find_java()
    bt = find_build_tools()
    adb = find_adb()
    rows = [
        ("java", str(java) if java else "MISSING"),
        ("build-tools", str(bt) if bt else "MISSING"),
        ("apksigner", str(tool("apksigner", bt)) if bt else "-"),
        ("zipalign", str(tool("zipalign", bt)) if bt else "-"),
        ("adb", str(adb) if adb else "MISSING"),
        ("apktool.jar", str(APKTOOL_JAR) if APKTOOL_JAR.exists() else "not downloaded"),
        ("keystore", str(KS) if KS.exists() else "not created"),
    ]
    for k, v in rows:
        print(f"  {k:14s} {v}")
    if adb:
        p = run([adb, "devices"], check=False)
        print("  --- adb devices ---")
        for line in p.stdout.splitlines():
            print("  " + line)
    return 0 if (java and bt and adb) else 1


def cmd_init(a):
    java = find_java() or die("java not found")
    ensure_apktool(java)
    ok("ready")
    return 0


def cmd_cert(a):
    java = find_java() or die("java not found")
    kt = Path(java).parent / ("keytool.exe" if os.name == "nt" else "keytool")
    if not kt.exists():
        w = shutil.which("keytool")
        kt = Path(w) if w else None
    if not kt:
        die("keytool not found (expected next to java)")

    if KS.exists() and not a.force:
        warn(f"{KS} exists - reusing (use --force to regenerate)")
    else:
        info("generating keystore")
        run([
            kt, "-genkeypair", "-keystore", str(KS), "-alias", "k",
            "-keyalg", "RSA", "-keysize", "2048", "-validity", "10000",
            "-storepass", KS_PASS, "-keypass", KS_PASS,
            "-dname", "CN=release, OU=x, O=x, L=x, S=x, C=IN",
        ])

    p = run([kt, "-list", "-v", "-keystore", str(KS), "-alias", "k",
             "-storepass", KS_PASS], check=False)
    m = re.search(r"SHA256:\s*([0-9A-F:]{95})", p.stdout)
    if not m:
        die("could not parse SHA-256 from keytool output")
    digest = m.group(1).replace(":", "").lower()
    ok(f"keystore SHA-256 = {digest}")
    (HERE / "cert_sha256.txt").write_text(digest + "\n", encoding="utf-8")
    info("use this with:  patch <dir> --mode hash")
    return 0


def cmd_get(a):
    adb = find_adb() or die("adb not found")
    pkg = a.package
    out = Path(a.out or WORK / pkg)
    out.mkdir(parents=True, exist_ok=True)

    p = run([adb, "shell", "pm", "path", pkg], check=False)
    paths = [ln.strip().replace("package:", "")
             for ln in p.stdout.splitlines() if ln.strip().startswith("package:")]
    if not paths:
        die(f"package not installed: {pkg}")

    pulled = []
    for i, remote in enumerate(paths):
        local = out / f"split_{i:02d}.apk"
        info(f"pull {remote}")
        run([adb, "pull", remote, str(local)])
        pulled.append(local)

    # the base apk is the one named base.apk; apktool wants it merged anyway
    info(f"{len(pulled)} apk(s) -> {out}")
    for f in pulled:
        print(f"  {f.name}  {f.stat().st_size/1e6:.1f} MB")
    (out / "base.apk").exists() or (pulled and shutil.copy(pulled[0], out / "base.apk"))
    (out / "splits.txt").write_text("\n".join(str(x) for x in pulled) + "\n", encoding="utf-8")
    return 0


def cmd_decode(a):
    java = find_java() or die("java not found")
    ensure_apktool(java)
    apk = Path(a.apk)
    if not apk.exists():
        die(f"no such apk: {apk}")
    out = Path(a.out or apk.with_suffix(""))
    if out.exists() and not a.force:
        die(f"{out} exists (use --force)")
    if out.exists():
        shutil.rmtree(out)
    info(f"decode {apk.name} -> {out}")
    p = apktool(java, ["d", "-f", "-o", str(out), str(apk)])
    if p.returncode != 0:
        die(f"apktool failed:\n{p.stdout}\n{p.stderr}")
    ok("decoded")
    return 0


def iter_smali(root):
    for p in Path(root).rglob("*.smali"):
        yield p


def parse_methods(smali_text):
    """yield (header, lines_body, start_line) for each .method block"""
    lines = smali_text.splitlines()
    i, n = 0, len(lines)
    while i < n:
        m = METHOD_HDR.match(lines[i].strip())
        if m:
            header = lines[i].strip()
            j = i + 1
            depth = 1
            while j < n:
                s = lines[j].strip()
                if s.startswith(".method"):
                    depth += 1
                elif END_METHOD.match(s):
                    depth -= 1
                    if depth == 0:
                        break
                j += 1
            yield header, lines[i + 1:j], i + 1
            i = j + 1
        else:
            i += 1


def cmd_analyze(a):
    root = Path(a.dir)
    if not root.is_dir():
        die(f"no such dir: {root}")
    app_prefix = (getattr(a, "app_prefix", None) or "").replace(".", "/")

    findings = []
    files = 0
    for f in iter_smali(root):
        files += 1
        try:
            text = f.read_text(encoding="utf-8", errors="replace")
        except Exception:
            continue
        if not any(t in text for t in SIG_TOKENS):
            continue
        rel = str(f.relative_to(root)).replace("\\", "/")
        is_sdk = any(p in rel for p in SDK_PREFIXES)
        for header, body, start in parse_methods(text):
            blob = "\n".join(body)
            hits = [t for t in SIG_TOKENS if t in blob]
            if len(hits) < 2:
                continue
            ret = header.rsplit(")", 1)[-1].strip()
            has_cond = bool(COND_BRANCH.search(blob))
            has_hex = bool(HEX_STR.search(blob))
            strong = len([h for h in hits if h in SIG_STRONG])

            score = len(hits) + strong
            score += 6 if has_cond else 0
            score += 5 if has_hex else 0
            score += 3 if ret in ("Z", "I") else 0
            score -= 12 if is_sdk else 0

            if app_prefix and app_prefix.replace(".", "/") in rel and not is_sdk:
                score += 4

            kind = "noise"
            is_ctor = any(t in header for t in NEVER_ENFORCE)
            if not is_sdk and not is_ctor and (has_hex or ret == "Z") and strong >= 2:
                kind = "ENFORCE"
            elif not is_sdk and not is_ctor and has_cond and strong >= 3 and ret == "Z":
                kind = "ENFORCE"
            elif is_sdk:
                kind = "sdk"

            findings.append({
                "file": rel,
                "line": start,
                "header": header,
                "hits": hits,
                "ret": ret,
                "cond": has_cond,
                "hex": has_hex,
                "kind": kind,
                "score": score,
            })

    # also: literal hex hashes that look like cert digests
    literals = []
    for f in iter_smali(root):
        try:
            text = f.read_text(encoding="utf-8", errors="replace")
        except Exception:
            continue
        for m in HEX_STR.finditer(text):
            literals.append({"file": str(f.relative_to(root)), "value": m.group(2)})

    uniq = {}
    for it in literals:
        uniq.setdefault(it["value"], []).append(it["file"])

    findings.sort(key=lambda x: (-x["score"], x["file"]))
    enforce = [c for c in findings if c["kind"] == "ENFORCE"]
    sdk = [c for c in findings if c["kind"] == "sdk"]
    rest = [c for c in findings if c["kind"] == "noise"]
    report = {"scanned_smali_files": files,
              "enforce": len(enforce), "sdk": len(sdk), "noise": len(rest),
              "candidates": findings,
              "hex_literals": [{"value": k, "files": sorted(set(v))} for k, v in uniq.items()]}
    (HERE / "report.json").write_text(json.dumps(report, indent=2), encoding="utf-8")

    print(f"  smali files scanned : {files}")
    print(f"  ENFORCE candidates  : {len(enforce)}")
    print(f"  sdk reads (noise)   : {len(sdk)}")
    print(f"  unclassified        : {len(rest)}")
    print(f"  hex literals        : {len(report['hex_literals'])}")

    if enforce:
        print("\n  === ENFORCE (app's own signature check) ===")
        for c in enforce[:a.top]:
            flags = []
            if c["cond"]:
                flags.append("conditional")
            if c["hex"]:
                flags.append("has-hash-literal")
            print(f"  [{c['score']:2d}] {c['file']}:{c['line']}  ret={c['ret']}  {'+'.join(flags) or '-'}")
            print(f"       {c['header']}")
    else:
        print("\n  === ENFORCE: none ===")
        print("  app does not check its own signature. nothing to patch here.")
        print("  see hex literals below for re-sign risk, or check native .so.")

    if rest:
        print("\n  --- unclassified (inspect manually) ---")
        for c in rest[:min(a.top, 8)]:
            print(f"  [{c['score']:2d}] {c['file']}:{c['line']}  {c['header'][:100]}")

    if report["hex_literals"]:
        print("\n  --- hash-like literals (re-sign will change these) ---")
        for h in report["hex_literals"][:a.top]:
            print(f"  {h['value']}  ({len(h['files'])} file(s))")
            for ff in h["files"][:3]:
                print(f"       {ff}")
    print(f"\n  full report -> {HERE/'report.json'}")
    return 0


def stub_for(ret):
    if ret in ("Z", "I", "J", "S", "B"):
        return ["    .locals 1", "", "    const/4 v0, 0x1", "", "    return v0"]
    if ret == "V":
        return ["    .locals 0", "", "    return-void"]
    if ret == "Ljava/lang/String;":
        return ["    .locals 1", "", '    const-string v0, ""', "", "    return-object v0"]
    return None


def cmd_patch(a):
    root = Path(a.dir)
    if not root.is_dir():
        die(f"no such dir: {root}")

    report_f = HERE / "report.json"
    if not report_f.exists():
        die("run 'analyze' first")
    report = json.loads(report_f.read_text(encoding="utf-8"))

    targets_marked = a.only_methods.split("||") if a.only_methods else None
    changed = 0

    if a.mode == "true":
        # group candidate headers by file
        by_file = {}
        for c in report["candidates"]:
            if targets_marked and c["header"] not in targets_marked:
                continue
            ret = c["header"].rsplit(")", 1)[-1].strip()
            if stub_for(ret) is None:
                warn(f"skip non-boolean method ({ret}): {c['header'][:90]}")
                continue
            by_file.setdefault(c["file"], set()).add(c["header"])

        for rel, headers in by_file.items():
            f = root / rel
            text = f.read_text(encoding="utf-8", errors="replace")
            lines = text.splitlines()
            out = []
            i, n = 0, len(lines)
            while i < n:
                m = METHOD_HDR.match(lines[i].strip())
                if m:
                    header = lines[i].strip()
                    j = i + 1
                    depth = 1
                    while j < n:
                        s = lines[j].strip()
                        if s.startswith(".method"):
                            depth += 1
                        elif END_METHOD.match(s):
                            depth -= 1
                            if depth == 0:
                                break
                        j += 1
                    if header in headers:
                        ret = header.rsplit(")", 1)[-1].strip()
                        stub = stub_for(ret)
                        out.append(lines[i])
                        out.extend(stub)
                        out.append("    .end method")
                        i = j + 1
                        changed += 1
                        continue
                out.append(lines[i])
                i += 1
            if a.dry_run:
                print(f"  DRY  {rel}: {len(headers)} method(s)")
            else:
                f.write_text("\n".join(out) + "\n", encoding="utf-8")
                print(f"  PATCHED {rel}: {len(headers)} method(s)")

    elif a.mode == "hash":
        sha = (a.hash or "").strip().lower()
        if not sha:
            cf = HERE / "cert_sha256.txt"
            if not cf.exists():
                die("no --hash given and cert_sha256.txt missing (run 'cert')")
            sha = cf.read_text(encoding="utf-8").strip()
        if not re.fullmatch(r"[0-9a-f]{64}", sha):
            die(f"bad sha256: {sha!r}")
        pad = sha + ":" + sha  # covers md5/sha1-ish layouts
        for f in iter_smali(root):
            text = f.read_text(encoding="utf-8", errors="replace")
            def rep(m):
                v = m.group(2)
                if len(v) == 64:
                    new = sha
                elif len(v) == 40:
                    new = hashlib.new("sha1", sha.encode()).hexdigest()
                else:
                    new = hashlib.new("md5", sha.encode()).hexdigest()
                return m.group(1) + new + m.group(3)
            new_text, k = HEX_STR.subn(rep, text)
            if k:
                if a.dry_run:
                    print(f"  DRY  {f.relative_to(root)}: {k} literal(s)")
                else:
                    f.write_text(new_text, encoding="utf-8")
                    print(f"  PATCHED {f.relative_to(root)}: {k} literal(s)")
                changed += k
    else:
        die("--mode must be true or hash")

    ok(f"{changed} edit(s){' (dry run)' if a.dry_run else ''}")
    return 0


def cmd_build(a):
    java = find_java() or die("java not found")
    ensure_apktool(java)
    bt = find_build_tools() or die("build-tools not found")
    d = Path(a.dir)
    if not d.is_dir():
        die(f"no such dir: {d}")
    if not KS.exists():
        die("keystore missing - run 'cert' first")

    out = Path(a.out or (d.name + "-signed.apk"))
    unsigned = d / "_unsigned.apk"
    aligned = d / "_aligned.apk"

    info("apktool build")
    p = apktool(java, ["b", str(d), "-o", str(unsigned)])
    if p.returncode != 0:
        die(f"apktool build failed:\n{p.stdout}\n{p.stderr}")

    info("zipalign")
    run([tool("zipalign", bt), "-p", "-f", "4", str(unsigned), str(aligned)])

    info("apksigner")
    p = run([
        tool("apksigner", bt), "sign",
        "--ks", str(KS), "--ks-pass", f"pass:{KS_PASS}",
        "--key-pass", f"pass:{KS_PASS}", "--ks-key-alias", "k",
        "--out", str(out), str(aligned),
    ], check=False)
    if p.returncode != 0:
        die(f"apksigner failed:\n{p.stdout}\n{p.stderr}")

    v = run([tool("apksigner", bt), "verify", "--print-certs", str(out)], check=False)
    print(v.stdout)
    for f in (unsigned, aligned):
        if f.exists():
            f.unlink()
    ok(f"-> {out}")
    return 0


def cmd_install(a):
    adb = find_adb() or die("adb not found")
    apk = Path(a.apk)
    if not apk.exists():
        die(f"no such apk: {apk}")

    if a.uninstall:
        info(f"uninstalling {a.uninstall}")
        run([adb, "uninstall"] + (["-k"] if a.keep_data else []) + [a.uninstall], check=False)

    info("install")
    p = run([adb, "install", "-r", "-d", str(apk)], check=False)
    print(p.stdout.strip())
    if p.returncode != 0:
        warn("install failed - see message above")
        return 1
    ok("installed")
    return 0


def cmd_run(a):
    for fn, arg in ((cmd_doctor, a), (cmd_get, a), (cmd_decode, a), (cmd_analyze, a)):
        rc = fn(arg)
        if rc:
            return rc
    info("stopped before patch - inspect report.json and pick a mode")
    return 0


# ----------------------------------------------------------------- main
def main():
    ap = argparse.ArgumentParser(prog="sigkill", description="APK signature-check pipeline")
    sub = ap.add_subparsers(dest="cmd", required=True)

    sub.add_parser("doctor").set_defaults(func=cmd_doctor)
    sub.add_parser("init").set_defaults(func=cmd_init)

    c = sub.add_parser("cert"); c.add_argument("--force", action="store_true"); c.set_defaults(func=cmd_cert)

    g = sub.add_parser("get"); g.add_argument("package"); g.add_argument("-o", "--out")
    g.set_defaults(func=cmd_get)

    d = sub.add_parser("decode"); d.add_argument("apk"); d.add_argument("-o", "--out")
    d.add_argument("--force", action="store_true"); d.set_defaults(func=cmd_decode)

    an = sub.add_parser("analyze"); an.add_argument("dir"); an.add_argument("--top", type=int, default=25)
    an.add_argument("--app-prefix", help="app package namespace, e.g. com.example.app")
    an.set_defaults(func=cmd_analyze)

    p = sub.add_parser("patch"); p.add_argument("dir")
    p.add_argument("--mode", choices=["true", "hash"], required=True)
    p.add_argument("--hash"); p.add_argument("--only-methods"); p.add_argument("--dry-run", action="store_true")
    p.set_defaults(func=cmd_patch)

    b = sub.add_parser("build"); b.add_argument("dir"); b.add_argument("-o", "--out")
    b.set_defaults(func=cmd_build)

    i = sub.add_parser("install"); i.add_argument("apk")
    i.add_argument("--uninstall"); i.add_argument("--keep-data", action="store_true")
    i.set_defaults(func=cmd_install)

    r = sub.add_parser("run"); r.add_argument("package"); r.add_argument("--top", type=int, default=25)
    r.set_defaults(func=cmd_run)

    a = ap.parse_args()
    if a.cmd in ("decode", "run") and not hasattr(a, "out"):
        a.out = None
    if a.cmd == "run" and not hasattr(a, "force"):
        a.force = True
    if a.cmd == "run" and not hasattr(a, "dir"):
        a.dir = str(WORK / a.package)
    sys.exit(a.func(a) or 0)


if __name__ == "__main__":
    main()
