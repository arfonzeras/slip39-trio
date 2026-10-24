#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
"""
Security guard for the Android app manifest. Run it on the MERGED manifest produced by the
build: libraries can add permissions through manifest merging, and the source manifest
would not show that.

Fails (exit 1) if the app:
  - requests any permission outside the allowlist (in particular android.permission.INTERNET),
  - allows backups (share B must never reach cloud backup),
  - is debuggable in a release build (pass --release),
  - exports a component that is neither allowlisted nor guarded by an android:permission.

Usage: check-manifest.py <AndroidManifest.xml> [--release]
"""
import sys
import xml.etree.ElementTree as ET

A = "{http://schemas.android.com/apk/res/android}"

ALLOWED_PERMISSIONS = {
    "android.permission.ACCESS_NETWORK_STATE",   # offline gate reads connectivity
    "android.permission.USE_BIOMETRIC",
    # Added by androidx.core to protect its own unexported receivers (not a capability).
    "com.alfonsoteran.slip39trio.DYNAMIC_RECEIVER_NOT_EXPORTED_PERMISSION",
}
ALLOWED_EXPORTED = set()   # e.g. the launcher activity, once the UI exists


def main() -> int:
    if len(sys.argv) < 2:
        print(__doc__)
        return 2
    path, release = sys.argv[1], "--release" in sys.argv[2:]
    root = ET.parse(path).getroot()
    errors = []

    for tag in ("uses-permission", "uses-permission-sdk-23"):
        for el in root.iter(tag):
            name = el.get(A + "name")
            if name not in ALLOWED_PERMISSIONS:
                errors.append(f"unexpected permission: {name}")

    app = root.find("application")
    if app is None:
        errors.append("no <application> element")
    else:
        if app.get(A + "allowBackup") != "false":
            errors.append('android:allowBackup must be "false"')
        if release and app.get(A + "debuggable") == "true":
            errors.append("release build is debuggable")
        for kind in ("activity", "activity-alias", "service", "receiver", "provider"):
            for el in app.iter(kind):
                name = el.get(A + "name")
                if el.get(A + "exported") != "true" or name in ALLOWED_EXPORTED:
                    continue
                guard = el.get(A + "permission")
                if guard:
                    # e.g. androidx.profileinstaller's receiver, guarded by android.permission.DUMP
                    print(f"note: exported {kind} {name} is guarded by {guard}")
                else:
                    errors.append(f"exported {kind} without a guarding permission: {name}")

    for e in errors:
        print("MANIFEST CHECK FAILED:", e)
    if not errors:
        print(f"manifest check OK: {path}")
    return 1 if errors else 0


if __name__ == "__main__":
    sys.exit(main())
