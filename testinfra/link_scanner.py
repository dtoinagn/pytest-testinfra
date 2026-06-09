"""
lnk_scanner.py
--------------
Recursively scans a directory for Windows shortcut (.lnk) files,
extracts the link target path, and parses the component name + version
from two common patterns:

  Pattern A – dash-separated suffix:   "SomeName - 1.14.0-1"
  Pattern B – backslash version folder: "\\component\\v1.0.1-rc1\\"

Results are written to a CSV file.

Usage:
    python lnk_scanner.py <root_dir> [--output results.csv] [--verbose]

Requirements:
    pip install pylnk3
"""

import argparse
import csv
import os
import re
import sys
from pathlib import Path
from typing import Optional

try:
    import pylnk3
except ImportError:
    sys.exit(
        "Missing dependency: run  pip install pylnk3  then try again."
    )

# ---------------------------------------------------------------------------
# Version-extraction patterns (applied in order; first match wins)
# ---------------------------------------------------------------------------
#
# Supported version formats:
#   1.14.0          plain numeric
#   1.14.0-1        numeric with build/patch suffix
#   v1.0.1          v-prefixed
#   v1.0.1-rc1      v-prefixed with pre-release label  (rc1, alpha2, beta3 …)
#   1.2.3-rc1       non-v-prefixed with pre-release label
#
# The core fragment: optional 'v', then MAJOR.MINOR[.PATCH[.BUILD]],
# then an optional dash + alphanumeric pre-release/build tag.
# ---------------------------------------------------------------------------

_VER = (
    r"v?"                            # optional 'v' prefix
    r"\d+\.\d+"                      # MAJOR.MINOR  (required)
    r"(?:\.\d+)*"                    # .PATCH, .BUILD … (0 or more)
    r"(?:-[a-zA-Z0-9]+(?:\.\d+)*)?" # optional -prerelease tag (e.g. -rc1, -1, -alpha2)
)

# Pattern A – "Component Name - 1.14.0-1"  (dash/en-dash separator in a segment)
# The separator dash is distinguished from the pre-release dash because the
# version part starts with a digit (or 'v' followed by a digit).
_PAT_DASH = re.compile(
    rf"(?P<component>.+?)\s*[-–]\s*(?P<version>{_VER})\s*$",
    re.IGNORECASE,
)

# Pattern B – "…\component\v1.0.1-rc1\" or "…\component\1.14.0-1\"
_PAT_BACKSLASH_V = re.compile(
    rf"\\(?P<component>[^\\]+)\\(?P<version>v\d[^\\]*)[\\]?$",
    re.IGNORECASE,
)
_PAT_BACKSLASH_BARE = re.compile(
    rf"\\(?P<component>[^\\]+)\\(?P<version>{_VER})[\\]?$",
    re.IGNORECASE,
)

# Catch-all: version folder anywhere mid-path (followed by another backslash)
_PAT_ANYWHERE_V = re.compile(
    rf"[/\\](?P<component>[^/\\]+)[/\\](?P<version>v\d[^/\\]*)[/\\]",
    re.IGNORECASE,
)
_PAT_ANYWHERE_BARE = re.compile(
    rf"[/\\](?P<component>[^/\\]+)[/\\](?P<version>{_VER})[/\\]",
    re.IGNORECASE,
)


def extract_component_version(path_str: str) -> tuple[Optional[str], Optional[str]]:
    """
    Try each pattern against *path_str* and return (component, version).
    Returns (None, None) if nothing matches.
    """
    if not path_str:
        return None, None

    # 1. Dash pattern – check individual path segments first (most specific),
    #    then fall back to the full string.
    segments = path_str.replace("/", "\\").split("\\")
    for segment in segments + [path_str]:
        m = _PAT_DASH.match(segment.strip())
        if m:
            return m.group("component").strip(), m.group("version").strip().lstrip("vV")

    # 2. Backslash + explicit 'v' prefix
    m = _PAT_BACKSLASH_V.search(path_str)
    if m:
        return m.group("component").strip(), m.group("version").strip().lstrip("vV")

    # 3. Backslash bare numeric version folder
    m = _PAT_BACKSLASH_BARE.search(path_str)
    if m:
        return m.group("component").strip(), m.group("version").strip().lstrip("vV")

    # 4. Anywhere in the path with 'v' prefix
    m = _PAT_ANYWHERE_V.search(path_str)
    if m:
        return m.group("component").strip(), m.group("version").strip().lstrip("vV")

    # 5. Anywhere bare
    m = _PAT_ANYWHERE_BARE.search(path_str)
    if m:
        return m.group("component").strip(), m.group("version").strip().lstrip("vV")

    return None, None


def read_lnk_target(lnk_path: Path) -> tuple[Optional[str], Optional[str]]:
    """
    Open a .lnk file and return (local_base_path, working_directory).
    Returns (None, None) on failure.
    """
    try:
        lnk = pylnk3.parse(str(lnk_path))
        target = getattr(lnk, "local_base_path", None) or ""
        workdir = getattr(lnk, "working_dir", None) or ""
        return target or None, workdir or None
    except Exception:
        return None, None


def scan_directory(root: Path, verbose: bool = False) -> list[dict]:
    """
    Walk *root* recursively, process every .lnk file, and return a list
    of result dicts.
    """
    results = []
    lnk_files = sorted(root.rglob("*.lnk"))

    if not lnk_files:
        print(f"No .lnk files found under: {root}")
        return results

    print(f"Found {len(lnk_files)} shortcut(s) under: {root}\n")

    for lnk_path in lnk_files:
        target, workdir = read_lnk_target(lnk_path)

        # Try to extract from target first, then working directory
        component, version = extract_component_version(target or "")
        if not component:
            component, version = extract_component_version(workdir or "")

        row = {
            "shortcut_file": str(lnk_path),
            "shortcut_name": lnk_path.stem,
            "target_path": target or "",
            "working_dir": workdir or "",
            "component": component or "",
            "version": version or "",
        }
        results.append(row)

        if verbose:
            status = "✓" if component else "?"
            print(
                f"  [{status}] {lnk_path.name}\n"
                f"       target : {target}\n"
                f"       component: {component}   version: {version}\n"
            )

    return results


def write_csv(results: list[dict], output_path: Path) -> None:
    fieldnames = [
        "shortcut_file",
        "shortcut_name",
        "target_path",
        "working_dir",
        "component",
        "version",
    ]
    with output_path.open("w", newline="", encoding="utf-8") as fh:
        writer = csv.DictWriter(fh, fieldnames=fieldnames)
        writer.writeheader()
        writer.writerows(results)
    print(f"\nResults saved to: {output_path}")


def main() -> None:
    parser = argparse.ArgumentParser(
        description="Scan .lnk files and extract component name + version."
    )
    parser.add_argument(
        "root_dir",
        help="Root directory to scan recursively for .lnk files.",
    )
    parser.add_argument(
        "--output",
        default="lnk_scan_results.csv",
        help="Output CSV file path (default: lnk_scan_results.csv).",
    )
    parser.add_argument(
        "--verbose",
        action="store_true",
        help="Print per-file details while scanning.",
    )
    args = parser.parse_args()

    root = Path(args.root_dir).expanduser().resolve()
    if not root.is_dir():
        sys.exit(f"Error: '{root}' is not a valid directory.")

    results = scan_directory(root, verbose=args.verbose)
    if results:
        write_csv(results, Path(args.output))

        matched = sum(1 for r in results if r["component"])
        print(
            f"\nSummary: {len(results)} shortcut(s) scanned, "
            f"{matched} with component/version extracted, "
            f"{len(results) - matched} unmatched."
        )


if __name__ == "__main__":
    main()
