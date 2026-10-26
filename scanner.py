"""
RepoRescue AI — Scanner
Primary scan method: downloads repo as ZIP (no GitHub API rate limit).
Falls back to GitHub API tree only if ZIP download fails.
"""

import re
import os
import io
import zipfile
import time
from urllib.parse import urlparse
import requests

API_BASE  = "https://api.github.com"
TIMEOUT   = 30
MAX_FILES = 60
MAX_FILE_BYTES  = 150_000
MAX_TOTAL_BYTES = 2_000_000
MAX_ZIP_BYTES   = 50 * 1024 * 1024   # 50 MB safety cap for the zip download

SKIP_DIRS = {
    "node_modules", "vendor", ".git", "dist", "build", "__pycache__",
    ".venv", "venv", "coverage", "site-packages",
}
ALLOWED_EXTENSIONS = {
    # Code
    ".py", ".js", ".jsx", ".ts", ".tsx", ".java", ".go", ".php", ".rb", ".sh",
    ".cs", ".cpp", ".c", ".h", ".swift", ".kt", ".rs", ".dart", ".vue", ".svelte",
    ".scala", ".r", ".m", ".pl", ".lua", ".ex", ".exs", ".clj", ".hs",
    # Config / data
    ".yaml", ".yml", ".json", ".toml", ".env", ".xml", ".sql", ".tf",
    ".ini", ".cfg", ".conf", ".properties", ".gradle", ".cmake",
    # Docs / web
    ".md", ".txt", ".html", ".htm", ".css", ".scss", ".sass",
    # Notebooks
    ".ipynb",
}

RULES = [
    {
        "id": "PY-EVAL-001",
        "pattern": re.compile(r"\b(eval|exec)\s*\("),
        "rule": "Dynamic code execution",
        "severity": "High",
        "description": "eval() or exec() can execute dynamically supplied code. Review the input source and whether a safer alternative is possible.",
        "extensions": {".py"},
    },
    {
        "id": "SEC-SECRET-001",
        "pattern": re.compile(r"""(?i)\b(api[_-]?key|secret|password|token)\b\s*[:=]\s*['"][^'"\n]{8,}['"]"""),
        "rule": "Possible hardcoded secret",
        "severity": "High",
        "description": "A string assigned to a secret-like variable may contain a credential. Confirm whether it is real; use environment variables or a secret manager for actual secrets.",
        "extensions": None,
    },
    {
        "id": "PY-EXCEPT-001",
        "pattern": re.compile(r"\bexcept\s*:\s*$"),
        "rule": "Bare except clause",
        "severity": "Medium",
        "description": "A bare except catches nearly every exception, including interrupts. Catch specific exception types where practical.",
        "extensions": {".py"},
    },
    {
        "id": "PY-SHELL-001",
        "pattern": re.compile(r"subprocess\.(run|Popen|call|check_output)\s*\([^)]*shell\s*=\s*True", re.S),
        "rule": "Subprocess with shell=True",
        "severity": "High",
        "description": "shell=True can be dangerous when command content includes untrusted input. Prefer argument lists and shell=False when possible.",
        "extensions": {".py"},
    },
    {
        "id": "PY-DEBUG-001",
        "pattern": re.compile(r"^\s*(print\s*\(|breakpoint\s*\()", re.M),
        "rule": "Possible debug statement",
        "severity": "Low",
        "description": "A print() or breakpoint() call may be leftover debugging code. Check whether it belongs in production.",
        "extensions": {".py"},
    },
    {
        "id": "PY-REQUEST-TIMEOUT-001",
        "pattern": re.compile(r"requests\.(get|post|put|delete|patch|head)\s*\("),
        "rule": "HTTP request may lack timeout",
        "severity": "Low",
        "description": "Network requests without a timeout can hang for a long time. Confirm whether a timeout is supplied in the call.",
        "extensions": {".py"},
        "requires_missing": r"\btimeout\s*=",
    },
]


# ─────────────────────────── helpers ──────────────────────────────────────────

def parse_github_url(url: str):
    url = url.strip().replace("\\", "/").rstrip("/")
    parsed = urlparse(url)
    if parsed.scheme != "https" or parsed.netloc.lower() not in {"github.com", "www.github.com"}:
        raise ValueError("Enter a valid public GitHub URL beginning with https://github.com/")
    parts = [p for p in parsed.path.strip("/").split("/") if p]
    if len(parts) < 2:
        raise ValueError("URL must include both owner and repository, e.g. https://github.com/psf/requests")
    owner, repo = parts[0], parts[1]
    repo = repo.removesuffix(".git")
    return owner, repo


def _extension(path: str) -> str:
    name = path.rsplit("/", 1)[-1]
    return ("." + name.rsplit(".", 1)[-1].lower()) if "." in name else ""


def _should_skip(path: str) -> bool:
    return any(part in SKIP_DIRS for part in path.split("/"))


def _findings_for_file(path: str, content: str) -> list:
    ext = _extension(path)
    findings = []
    lines = content.splitlines()
    for rule in RULES:
        if rule["extensions"] and ext not in rule["extensions"]:
            continue
        for i, line in enumerate(lines, start=1):
            if rule["pattern"].search(line):
                if rule.get("requires_missing"):
                    nearby = "\n".join(lines[max(0, i - 2):min(len(lines), i + 2)])
                    if re.search(rule["requires_missing"], nearby):
                        continue
                findings.append({
                    "rule_id":     rule["id"],
                    "rule":        rule["rule"],
                    "severity":    rule["severity"],
                    "path":        path,
                    "line":        i,
                    "description": rule["description"],
                    "evidence":    line.strip()[:500],
                })
                if sum(1 for f in findings if f["rule_id"] == rule["id"]) >= 3:
                    break
    return findings


def _auth_headers() -> dict:
    h = {"User-Agent": "RepoRescueAI-Hackathon-MVP"}
    token = os.getenv("GITHUB_TOKEN", "")
    if token:
        h["Authorization"] = f"Bearer {token}"
    return h


# ─────────────────────── ZIP-based scan (NO rate limit) ───────────────────────

def _scan_via_zip(owner: str, repo: str):
    """
    Downloads the repo archive from github.com (not the API).
    This endpoint has NO rate limiting — works without any token.
    Returns (result_dict) or raises on failure.
    """
    branch = None
    zip_bytes = None

    for candidate in ["main", "master"]:
        url = f"https://github.com/{owner}/{repo}/archive/refs/heads/{candidate}.zip"
        try:
            resp = requests.get(url, headers=_auth_headers(), timeout=TIMEOUT, stream=True)
            if resp.status_code == 404:
                continue
            if resp.status_code != 200:
                continue
            # Stream with size cap
            chunks = []
            total = 0
            for chunk in resp.iter_content(chunk_size=65536):
                chunks.append(chunk)
                total += len(chunk)
                if total > MAX_ZIP_BYTES:
                    break
            zip_bytes = b"".join(chunks)
            branch = candidate
            break
        except requests.RequestException:
            continue

    if not zip_bytes or not branch:
        raise ConnectionError("Could not download repository archive. Check the URL and your connection.")

    try:
        zf = zipfile.ZipFile(io.BytesIO(zip_bytes))
    except zipfile.BadZipFile:
        raise ValueError("Downloaded file is not a valid zip archive.")

    # Determine top-level prefix (github zips always add "{repo}-{branch}/")
    names = zf.namelist()
    prefix = ""
    top_dirs = {n.split("/")[0] + "/" for n in names if "/" in n}
    if len(top_dirs) == 1:
        prefix = list(top_dirs)[0]

    # Build flat file list
    all_files = []
    for zip_name in names:
        if zip_name.endswith("/"):
            continue
        rel_path = zip_name[len(prefix):] if prefix and zip_name.startswith(prefix) else zip_name
        if rel_path:
            all_files.append((zip_name, rel_path))

    total_files = len(all_files)

    # Apply filters
    candidates = [
        (zn, rp) for zn, rp in all_files
        if not _should_skip(rp)
        and _extension(rp) in ALLOWED_EXTENSIONS
        and zf.getinfo(zn).file_size <= MAX_FILE_BYTES
    ][:MAX_FILES]

    skipped_ext  = [rp for _, rp in all_files if not _should_skip(rp) and _extension(rp) not in ALLOWED_EXTENSIONS]
    skipped_size = [rp for zn, rp in all_files if not _should_skip(rp) and zf.getinfo(zn).file_size > MAX_FILE_BYTES]

    findings = []
    files_scanned = 0
    scanned_list = []
    total_bytes = 0

    for zip_name, rel_path in candidates:
        if total_bytes >= MAX_TOTAL_BYTES:
            break
        try:
            raw = zf.read(zip_name)
            if len(raw) > MAX_FILE_BYTES:
                continue
            total_bytes += len(raw)
            content = raw.decode("utf-8", errors="replace")
            files_scanned += 1
            scanned_list.append(rel_path)
            findings.extend(_findings_for_file(rel_path, content))
        except Exception:
            continue

    severity_order = {"High": 0, "Medium": 1, "Low": 2}
    findings.sort(key=lambda f: (severity_order.get(f["severity"], 9), f["path"], f["line"]))

    return {
        "full_name":     f"{owner}/{repo}",
        "branch":        branch,
        "total_files":   total_files,
        "files_scanned": files_scanned,
        "scanned_list":  scanned_list,
        "skipped_ext":   skipped_ext,
        "skipped_size":  skipped_size,
        "tree_truncated": total_bytes >= MAX_ZIP_BYTES,
        "findings":      findings[:100],
        "method":        "zip",
    }


# ─────────────── API-based scan (fallback, subject to rate limit) ──────────────

def _get_json(url, params=None, retries=3):
    headers = {
        "Accept": "application/vnd.github+json",
        "X-GitHub-Api-Version": "2022-11-28",
        **_auth_headers(),
    }
    last_exc = None
    for attempt in range(retries):
        try:
            resp = requests.get(url, headers=headers, params=params, timeout=TIMEOUT)
            if resp.status_code == 404:
                raise ValueError("Repository not found or private.")
            if resp.status_code == 403:
                reset_ts = resp.headers.get("X-RateLimit-Reset", "")
                if reset_ts:
                    reset_in = max(0, int(reset_ts) - int(time.time()))
                    msg = f"GitHub API rate limit hit. Resets in {reset_in // 60}m {reset_in % 60}s."
                else:
                    msg = "GitHub API rate limit hit."
                raise ValueError(msg)
            resp.raise_for_status()
            return resp.json()
        except ValueError:
            raise
        except Exception as exc:
            last_exc = exc
            if attempt < retries - 1:
                time.sleep(2)
    raise last_exc


# ──────────────────────────── public entry point ───────────────────────────────

def scan_github_repository(url: str) -> dict:
    owner, repo = parse_github_url(url)
    # Primary: ZIP download — no rate limit at all
    return _scan_via_zip(owner, repo)
