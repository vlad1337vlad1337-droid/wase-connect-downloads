#!/usr/bin/env python3
"""Offline public-documentation gate. Does not prove binary or network safety."""

import argparse
import datetime
import json
import re
import subprocess
import sys
import xml.etree.ElementTree as ET
from pathlib import Path
from urllib.parse import unquote, urlsplit


ROOT_FILES = {
    "README.md", "CONTRIBUTING.md", "CHANGELOG.md", "SECURITY.md",
    "THIRD-PARTY-NOTICES.md", ".gitignore", ".gitattributes", "release-status.json",
}
CI_SCRIPTS = {
    ".github/scripts/check_public_repository.py",
    ".github/scripts/test_public_repository.py",
}
DIRECTORY_TYPES = {
    "docs": {".md"}, "assets": {".svg", ".png", ".txt"},
    ".github": {".md", ".yml"},
}
PATTERNS = {
    "private key": r"-----BEGIN (?:RSA |EC |OPENSSH |DSA )?PRIVATE KEY-----",
    "GitHub token": r"\b(?:gh[pousr]_[A-Za-z0-9]{30,}|github_pat_[A-Za-z0-9_]{50,})\b",
    "AWS access key": r"\bAKIA[A-Z0-9]{16}\b",
    "live subscription URL": r"https?://[^\s\x22\x27<>]+/(?:sub|subscription)/[A-Za-z0-9_-]{24,}",
    "personal filesystem path": r"(?:/Users/|/home/)[A-Za-z0-9_.-]+/|[A-Za-z]:\\Users\\[A-Za-z0-9_. -]+\\",
    "URL credentials": r"https?://[^\s/@:]+:[^\s/@]+@",
    "private source repository link": r"https://github\.com/vlad1337vlad1337-droid/wase-connect(?:[/#?\s)]|$)",
}


def allowed_path(path):
    name = path.as_posix()
    if name in ROOT_FILES or name in CI_SCRIPTS:
        return True
    return len(path.parts) > 1 and path.suffix in DIRECTORY_TYPES.get(path.parts[0], set())


def repository_files(root):
    result = subprocess.run(
        ["git", "ls-files", "-z", "--cached", "--others", "--exclude-standard"],
        cwd=root, capture_output=True, check=True,
    )
    return sorted({Path(name.decode("utf-8")) for name in result.stdout.split(b"\0") if name})


def validate_status(value):
    required = {"schemaVersion", "publicStableRelease", "downloads", "status", "updatedAt", "reason"}
    if not isinstance(value, dict) or set(value) != required:
        return ["release status must have exactly the documented fields"]
    errors = []
    if type(value["schemaVersion"]) is not int or value["schemaVersion"] != 1:
        errors.append("release status schema must be 1")
    # Opening public binary distribution is a separate reviewed change, never a docs side effect.
    if value["status"] != "preparing" or value["publicStableRelease"] is not None or value["downloads"] != []:
        errors.append("public release is gated: expected preparing, null stable release and no downloads")
    try:
        date = value["updatedAt"]
        if not isinstance(date, str) or not re.fullmatch(r"\d{4}-\d{2}-\d{2}", date):
            raise ValueError("date")
        datetime.date.fromisoformat(date)
    except (ValueError, TypeError):
        errors.append("release status date must be YYYY-MM-DD")
    if not isinstance(value["reason"], str) or not value["reason"].strip():
        errors.append("release status needs a reason")
    return errors


def markdown_destinations(text):
    # Ignore fenced examples; accept inline links/images and reference-link definitions.
    prose = re.sub(r"(?ms)^\s*(```|~~~).*?^\s*\1\s*$", "", text)
    inline = re.findall(r"\]\((<[^>]+>|[^\s)]+)(?:\s+[\"'][^\n]*?[\"'])?\)", prose)
    references = re.findall(r"(?m)^\s*\[[^\]]+\]:\s*(<[^>]+>|\S+)", prose)
    return [destination.strip("<>") for destination in inline + references]


def local_link_errors(root, relative, text, files):
    errors = []
    for destination in markdown_destinations(text):
        parsed = urlsplit(destination)
        if parsed.scheme or parsed.netloc or not parsed.path:
            continue
        path = unquote(parsed.path)
        target = (root / relative.parent / path).resolve()
        if not target.is_relative_to(root):
            errors.append("local link escapes repository")
        elif target.relative_to(root) not in files or not target.is_file():
            errors.append("local link target missing: " + path)
    return errors


def svg_errors(data):
    errors = []
    if b"<!DOCTYPE" in data.upper() or b"<!ENTITY" in data.upper():
        return ["SVG declarations are not allowed"]
    try:
        tree = ET.fromstring(data)
    except ET.ParseError:
        return ["invalid SVG"]
    for element in tree.iter():
        tag = element.tag.split("}")[-1].lower()
        if tag in {"script", "foreignobject", "iframe", "audio", "video"}:
            errors.append("active SVG content")
        if tag == "style" and element.text and re.search(r"@import|url\(\s*['\"]?(?!#)[^\s)]", element.text, re.I):
            errors.append("SVG external stylesheet resource")
        for key, value in element.attrib.items():
            local_key = key.split("}")[-1].lower()
            if local_key.startswith("on"):
                errors.append("SVG event handler")
            if local_key in {"href", "src"} and value and not value.startswith("#"):
                errors.append("SVG external resource")
            if re.search(r"url\(\s*['\"]?(?!#)[^\s)]", value, re.I):
                errors.append("SVG external CSS resource")
    return sorted(set(errors))


def audit(root, paths=None):
    root = root.resolve()
    paths = repository_files(root) if paths is None else paths
    active = {path for path in paths if (root / path).exists() or (root / path).is_symlink()}
    issues = []
    for relative in sorted(active):
        path = root / relative
        def fail(message, line=None):
            issue = {"file": relative.as_posix(), "error": message}
            if line is not None:
                issue["line"] = line
            issues.append(issue)
        if path.is_symlink():
            fail("symlinks are not allowed")
            continue
        if not allowed_path(relative):
            fail("outside public documentation/branding/CI allowlist")
            continue
        if path.stat().st_size > 2_000_000:
            fail("file exceeds public documentation size limit")
            continue
        data = path.read_bytes()
        if relative.suffix == ".svg":
            for message in svg_errors(data):
                fail(message)
        if relative.suffix == ".png":
            if not data.startswith(b"\x89PNG\r\n\x1a\n"):
                fail("invalid PNG signature")
            continue
        try:
            text = data.decode("utf-8")
        except UnicodeDecodeError:
            fail("expected UTF-8 text")
            continue
        if re.search(r"[\x00-\x08\x0b\x0c\x0e-\x1f]", text):
            fail("unexpected binary/control bytes in text")
            continue
        for number, line in enumerate(text.splitlines(), 1):
            for kind, pattern in PATTERNS.items():
                if re.search(pattern, line):
                    fail(kind, number)
        if relative.suffix == ".md":
            for message in local_link_errors(root, relative, text, active):
                fail(message)
        if relative.as_posix() == "release-status.json":
            try:
                for message in validate_status(json.loads(text)):
                    fail(message)
            except json.JSONDecodeError:
                fail("invalid release status JSON")
    for required in ROOT_FILES:
        if Path(required) not in active:
            issues.append({"file": required, "error": "required public file missing"})
    return {"files": len(active), "issues": issues}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--root", type=Path, default=Path(__file__).resolve().parents[2])
    args = parser.parse_args()
    try:
        result = audit(args.root)
    except (OSError, subprocess.CalledProcessError) as error:
        print(json.dumps({"error": "Unable to inspect public repository", "kind": type(error).__name__}))
        return 1
    print(json.dumps(result, ensure_ascii=False, indent=2))
    return 1 if result["issues"] else 0


if __name__ == "__main__":
    sys.exit(main())
