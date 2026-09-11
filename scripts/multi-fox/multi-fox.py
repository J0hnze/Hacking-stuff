#!/usr/bin/env python3

import argparse
import json
import os
import platform
import shutil
import subprocess
import sys
import time
from pathlib import Path

# =========================================================
# CONFIG
# =========================================================

TARGET_URL = "https://duckduckgo.com/"

BURP_PROXY_HOST = "127.0.0.1"
BURP_PROXY_PORT = 8080

BURP_LAUNCH_WAIT_SECONDS = 8

PENTEST_DIR = Path.home() / "pentest"
EXTENSION_DIR = PENTEST_DIR / "firefox-extensions"
WAPPALYZER_XPI = EXTENSION_DIR / "wappalyzer.xpi"

PROFILE_MAP = {
    "user": {
        "folder": "green",
        "ua": "Firefox-Green",
        "hex": "#1f7a1f",
        "label": "USER (GREEN)",
    },

    "manager": {
        "folder": "blue",
        "ua": "Firefox-Blue",
        "hex": "#1f4e7a",
        "label": "MANAGER (BLUE)",
    },

    "admin": {
        "folder": "red",
        "ua": "Firefox-Red",
        "hex": "#7a1f1f",
        "label": "ADMIN (RED)",
    },
}

# =========================================================
# PLATFORM HELPERS
# =========================================================

def is_windows():
    return platform.system().lower() == "windows"


def get_base_dir():

    if is_windows():
        return Path(
            os.environ.get("TEMP", "C:\\Temp")
        ) / "firefox" / "profiles"

    return Path("/tmp/firefox/profiles")


def get_cert_path():
    return Path.home() / "certs" / "burp-ca.der"


# =========================================================
# UTILITY FUNCTIONS
# =========================================================

def find_binary(name):

    path = shutil.which(name)

    if not path:
        print(f"[-] Required binary not found in PATH: {name}")
        sys.exit(1)

    return path


def run(cmd, quiet=False):

    try:
        subprocess.run(
            cmd,
            check=True,
            stdout=subprocess.DEVNULL if quiet else None,
            stderr=subprocess.DEVNULL if quiet else None,
        )

    except subprocess.CalledProcessError as e:
        print(f"[-] Command failed: {' '.join(map(str, cmd))}")
        sys.exit(e.returncode)


# =========================================================
# BURP DETECTION
# =========================================================

def find_burp():

    system = platform.system().lower()

    possible_paths = []

    # =====================
    # WINDOWS
    # =====================

    if system == "windows":

        possible_paths = [
            r"C:\Program Files\BurpSuitePro\BurpSuitePro.exe",
            r"C:\Program Files\BurpSuiteCommunity\BurpSuiteCommunity.exe",
            r"C:\BurpSuitePro\BurpSuitePro.exe",
            r"C:\BurpSuiteCommunity\BurpSuiteCommunity.exe",
        ]

        for path in possible_paths:

            if Path(path).exists():
                return str(Path(path))

        for name in [
            "BurpSuitePro.exe",
            "BurpSuiteCommunity.exe"
        ]:

            found = shutil.which(name)

            if found:
                return found

    # =====================
    # LINUX / NIXOS / KALI
    # =====================

    else:

        for name in [
            "burpsuite",
            "burpsuitepro",
            "BurpSuitePro",
            "BurpSuiteCommunity",
            "burpsuite-community",
        ]:

            found = shutil.which(name)

            if found:
                return found

        possible_paths = [
            "/usr/bin/burpsuite",
            "/usr/local/bin/burpsuite",
            "/opt/BurpSuitePro/BurpSuitePro",
            "/opt/BurpSuiteCommunity/BurpSuiteCommunity",
        ]

        for path in possible_paths:

            if Path(path).exists():
                return str(Path(path))

    return None


def launch_burp():

    burp_path = find_burp()

    if not burp_path:

        print("[!] Burp Suite not found")
        print("[!] Ensure Burp is installed and available in PATH")
        return False

    print(f"[+] Launching Burp Suite: {burp_path}")

    subprocess.Popen(
        [burp_path],
        stdout=subprocess.DEVNULL,
        stderr=subprocess.DEVNULL,
    )

    return True


# =========================================================
# FIREFOX PROFILE SETUP
# =========================================================

def bootstrap_firefox_profile(
    firefox_bin,
    profile_dir
):

    proc = subprocess.Popen(
        [
            firefox_bin,
            "--headless",
            "--profile",
            str(profile_dir),
            "--no-remote",
        ],
        stdout=subprocess.DEVNULL,
        stderr=subprocess.DEVNULL,
    )

    time.sleep(3)

    proc.terminate()

    try:
        proc.wait(timeout=5)

    except subprocess.TimeoutExpired:
        proc.kill()


def write_user_js(
    profile_dir,
    profile
):

    user_js = f'''user_pref("network.proxy.type", 1);
user_pref("network.proxy.http", "{BURP_PROXY_HOST}");
user_pref("network.proxy.http_port", {BURP_PROXY_PORT});
user_pref("network.proxy.ssl", "{BURP_PROXY_HOST}");
user_pref("network.proxy.ssl_port", {BURP_PROXY_PORT});
user_pref("network.proxy.share_proxy_settings", true);
user_pref("network.proxy.no_proxies_on", "");
user_pref("network.proxy.allow_hijacking_localhost", true);

user_pref("general.useragent.override", "{profile["ua"]}");

user_pref("toolkit.legacyUserProfileCustomizations.stylesheets", true);

user_pref("security.enterprise_roots.enabled", true);

/* Disable telemetry */
user_pref("datareporting.healthreport.uploadEnabled", false);
user_pref("toolkit.telemetry.enabled", false);

/* Do not remember sign-ins */
user_pref("signon.rememberSignons", false);

/* Disable form history */
user_pref("browser.formfill.enable", false);

/* Disable history */
user_pref("places.history.enabled", false);

/* Clear everything on shutdown */
user_pref("privacy.clearOnShutdown.cookies", true);
user_pref("privacy.clearOnShutdown.history", true);
user_pref("privacy.clearOnShutdown.downloads", true);
user_pref("privacy.clearOnShutdown.formdata", true);
user_pref("privacy.clearOnShutdown.sessions", true);

user_pref("privacy.sanitize.sanitizeOnShutdown", true);

/* Extension install behaviour */
user_pref("extensions.autoDisableScopes", 0);
user_pref("extensions.enabledScopes", 15);
'''

    (
        profile_dir / "user.js"
    ).write_text(
        user_js,
        encoding="utf-8"
    )


def write_user_chrome(
    chrome_dir,
    profile
):

    user_chrome = f'''#navigator-toolbox,
#TabsToolbar {{
  background-color: {profile["hex"]} !important;
}}

#nav-bar {{
  color: white !important;
}}

#nav-bar::before {{
  content: "{profile["label"]}";
  font-weight: bold;
  color: white;
  margin-right: 15px;
  padding-left: 8px;
}}
'''

    (
        chrome_dir / "userChrome.css"
    ).write_text(
        user_chrome,
        encoding="utf-8"
    )


# =========================================================
# EXTENSIONS
# =========================================================

def install_extensions(profile_dir):

    extensions_dir = profile_dir / "extensions"

    extensions_dir.mkdir(
        parents=True,
        exist_ok=True
    )

    if WAPPALYZER_XPI.exists():

        shutil.copy2(
            WAPPALYZER_XPI,
            extensions_dir / "wappalyzer.xpi"
        )

        print("[+] Wappalyzer extension added")

    else:

        print(
            f"[!] Wappalyzer extension not found: "
            f"{WAPPALYZER_XPI}"
        )

        print(
            "[!] Download the extension and save as:"
        )

        print(
            f"    {WAPPALYZER_XPI}"
        )


# =========================================================
# WINDOWS POLICIES
# =========================================================

def write_windows_policy(profile_dir):

    distribution_dir = (
        profile_dir / "distribution"
    )

    distribution_dir.mkdir(
        parents=True,
        exist_ok=True
    )

    policies = {
        "policies": {

            "ImportEnterpriseRoots": True,

            "Extensions": {
                "Install": [
                    str(WAPPALYZER_XPI)
                ] if WAPPALYZER_XPI.exists() else []
            }
        }
    }

    (
        distribution_dir / "policies.json"
    ).write_text(
        json.dumps(
            policies,
            indent=2
        ),
        encoding="utf-8"
    )


# =========================================================
# LINUX BURP CERT IMPORT
# =========================================================

def import_burp_ca_linux(
    certutil_bin,
    cert_path,
    profile_dir,
    profile_name
):

    print(
        f"[+] Importing Burp CA into "
        f"{profile_name}"
    )

    run(
        [
            certutil_bin,
            "-A",
            "-n",
            "Burp CA",
            "-t",
            "C,,",
            "-i",
            str(cert_path),
            "-d",
            f"sql:{profile_dir}",
        ]
    )


# =========================================================
# CREATE PROFILE
# =========================================================

def create_profile(
    profile_name,
    firefox_bin,
    certutil_bin,
    cert_path,
    base_dir
):

    profile = PROFILE_MAP[profile_name]

    folder = profile["folder"]

    profile_dir = base_dir / folder
    chrome_dir = profile_dir / "chrome"

    print(
        f"[+] Creating profile: "
        f"{profile_name} ({folder})"
    )

    chrome_dir.mkdir(
        parents=True,
        exist_ok=True
    )

    bootstrap_firefox_profile(
        firefox_bin,
        profile_dir
    )

    write_user_js(
        profile_dir,
        profile
    )

    write_user_chrome(
        chrome_dir,
        profile
    )

    install_extensions(profile_dir)

    # =====================
    # WINDOWS
    # =====================

    if is_windows():

        print(
            f"[+] Enabling Windows "
            f"certificate trust for "
            f"{profile_name}"
        )

        write_windows_policy(profile_dir)

    # =====================
    # LINUX / NIXOS / KALI
    # =====================

    else:

        import_burp_ca_linux(
            certutil_bin,
            cert_path,
            profile_dir,
            profile_name,
        )

    print(f"[+] Profile ready: {profile_name}")


# =========================================================
# LAUNCH FIREFOX
# =========================================================

def launch_profile(
    profile_name,
    firefox_bin,
    base_dir
):

    folder = PROFILE_MAP[
        profile_name
    ]["folder"]

    profile_dir = base_dir / folder

    print(f"[+] Launching {profile_name}")

    subprocess.Popen(
        [
            firefox_bin,
            "--no-remote",
            "--new-instance",
            "--profile",
            str(profile_dir),
            TARGET_URL,
        ],
        stdout=subprocess.DEVNULL,
        stderr=subprocess.DEVNULL,
    )


# =========================================================
# PROFILE PARSING
# =========================================================

def parse_profiles(value):

    profiles = [
        p.strip().lower()
        for p in value.split(",")
        if p.strip()
    ]

    invalid = [
        p for p in profiles
        if p not in PROFILE_MAP
    ]

    if invalid:

        print(
            f"[-] Invalid profile(s): "
            f"{', '.join(invalid)}"
        )

        print(
            "[-] Valid profiles are: "
            "user, manager, admin"
        )

        sys.exit(1)

    return profiles


# =========================================================
# MAIN
# =========================================================

def main():

    parser = argparse.ArgumentParser(
        prog="multi-fox",
        description=(
            "Launch Firefox testing "
            "profiles through Burp."
        ),
    )

    parser.add_argument(
        "-p",
        "--profiles",
        required=True,
        help=(
            "Comma-separated profiles "
            "to launch."
        ),
    )

    parser.add_argument(
        "--burp",
        choices=["yes", "no"],
        default="no",
        help=(
            "Launch Burp Suite "
            "automatically."
        ),
    )

    parser.add_argument(
        "--keep-data",
        action="store_true",
        help=(
            "Keep existing Firefox "
            "profile data."
        ),
    )

    args = parser.parse_args()

    selected_profiles = parse_profiles(
        args.profiles
    )

    base_dir = get_base_dir()
    cert_path = get_cert_path()

    print("[+] Checking dependencies...")

    firefox_bin = find_binary(
        "firefox"
    )

    certutil_bin = None

    # =====================
    # WINDOWS
    # =====================

    if is_windows():

        print("[+] Windows detected")

        print(
            "[!] Ensure Burp CA is "
            "installed in Windows "
            "Trusted Root store"
        )

    # =====================
    # LINUX / NIXOS / KALI
    # =====================

    else:

        certutil_bin = find_binary(
            "certutil"
        )

        if not cert_path.exists():

            print(
                f"[-] Burp cert not found: "
                f"{cert_path}"
            )

            sys.exit(1)

    # =====================================================
    # RESET PROFILES
    # =====================================================

    if not args.keep_data:

        print(
            "[+] Erasing old Firefox "
            "profile data..."
        )

        shutil.rmtree(
            base_dir,
            ignore_errors=True
        )

    else:

        print(
            "[!] Keeping existing "
            "Firefox profile data"
        )

    base_dir.mkdir(
        parents=True,
        exist_ok=True
    )

    EXTENSION_DIR.mkdir(
        parents=True,
        exist_ok=True
    )

    # =====================================================
    # CREATE PROFILES
    # =====================================================

    for profile_name in PROFILE_MAP:

        create_profile(
            profile_name,
            firefox_bin,
            certutil_bin,
            cert_path,
            base_dir,
        )

    # =====================================================
    # BURP
    # =====================================================

    if args.burp == "yes":

        if launch_burp():

            print(
                "[+] Waiting for Burp "
                "to start..."
            )

            time.sleep(
                BURP_LAUNCH_WAIT_SECONDS
            )

    # =====================================================
    # LAUNCH FIREFOX
    # =====================================================

    for profile_name in selected_profiles:

        launch_profile(
            profile_name,
            firefox_bin,
            base_dir,
        )

    print(
        "[+] Selected profiles "
        "launched through Burp"
    )


if __name__ == "__main__":
    main()