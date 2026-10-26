import re
import os
import base64
from urllib.parse import urlparse
import requests

API_BASE = "https://api.github.com"
TIMEOUT = 12
MAX_FILES = 60
MAX_FILE_BYTES = 150_000
MAX_TOTAL_BYTES = 2_000_000

SKIP_DIRS = {
    "node_modules", "vendor", ".git", "dist", "build", "__pycache__",
    ".venv", "venv", "coverage", "site-packages"
}
ALLOWED_EXTENSIONS = {
    # Code files
    ".py", ".js", ".jsx", ".ts", ".tsx", ".java", ".go", ".php", ".rb", ".sh",
    ".cs", ".cpp", ".c", ".h", ".swift", ".kt", ".rs", ".dart", ".vue", ".svelte",
    ".scala", ".r", ".m", ".pl", ".lua", ".ex", ".exs", ".clj", ".hs",
    # Config / data files
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


def parse_github_url(url: str):
    # Strip whitespace, backslashes and trailing slashes that users often paste
    url = url.strip().replace("\\", "/").rstrip("/")
    parsed = urlparse(url)
    if parsed.scheme != "https" or parsed.netloc.lower() not in {"github.com", "www.github.com"}:
        raise ValueError("Enter a valid public GitHub URL beginning with https://github.com/")
    parts = [p for p in parsed.path.strip("/").split("/") if p]
    if len(parts) < 2:
        raise ValueError("URL must include both owner and repository, for example https://github.com/psf/requests")
    owner, repo = parts[0], parts[1]
    if owner in {".", ".."} or repo in {".", ".."}:
        raise ValueError("Invalid GitHub repository path")
    repo = repo.removesuffix(".git")
    return owner, repo


def _get_json(url, params=None, retries=3):
    import time
    token = os.getenv("GITHUB_TOKEN", "")
    headers = {
        "Accept": "application/vnd.github+json",
        "User-Agent": "RepoRescueAI-Hackathon-MVP",
        "X-GitHub-Api-Version": "2022-11-28",
    }
    if token:
        headers["Authorization"] = f"Bearer {token}"

    last_exc = None
    for attempt in range(retries):
        try:
            response = requests.get(url, headers=headers, params=params, timeout=TIMEOUT)
            if response.status_code == 404:
                raise ValueError("Repository not found, private, or inaccessible. This MVP supports public repositories only.")
            if response.status_code == 403:
                reset_ts = response.headers.get("X-RateLimit-Reset", "")
                if reset_ts:
                    reset_in = max(0, int(reset_ts) - int(time.time()))
                    msg = f"GitHub API rate limit hit. Resets in {reset_in // 60}m {reset_in % 60}s. "
                else:
                    msg = "GitHub API rate limit hit. "
                if not token:
                    msg += "Add GITHUB_TOKEN to .env for 5000 req/hr vs 60 without token."
                raise ValueError(msg)
            response.raise_for_status()
            return response.json()
        except ValueError:
            raise  # Don't retry 404/403 — they won't change
        except Exception as exc:
            last_exc = exc
            if attempt < retries - 1:
                time.sleep(2)  # Wait before retrying
    raise last_exc


def _extension(path):
    name = path.rsplit("/", 1)[-1]
    if "." not in name:
        return ""
    return "." + name.rsplit(".", 1)[-1].lower()


def _should_skip(path):
    return any(part in SKIP_DIRS for part in path.split("/"))


def _findings_for_file(path, content):
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
                    "rule_id": rule["id"],
                    "rule": rule["rule"],
                    "severity": rule["severity"],
                    "path": path,
                    "line": i,
                    "description": rule["description"],
                    "evidence": line.strip()[:500],
                })
                if sum(1 for f in findings if f["rule_id"] == rule["id"]) >= 3:
                    break
    return findings


def scan_github_repository(url: str):
    owner, repo = parse_github_url(url)
    full_name = f"{owner}/{repo}"

    # Try main then master without extra API call — saves 1 rate-limit request
    tree_data = None
    branch = None
    for candidate in ["main", "master"]:
        try:
            tree_data = _get_json(
                f"{API_BASE}/repos/{owner}/{repo}/git/trees/{candidate}",
                params={"recursive": "1"},
            )
            branch = candidate
            break
        except ValueError as e:
            if "not found" in str(e).lower() or "404" in str(e):
                continue
            raise

    if branch is None:
        # Fallback: fetch repo metadata to find actual default branch
        repo_data = _get_json(f"{API_BASE}/repos/{owner}/{repo}")
        full_name = repo_data.get("full_name", full_name)
        branch = repo_data.get("default_branch") or "main"
        tree_data = _get_json(
            f"{API_BASE}/repos/{owner}/{repo}/git/trees/{branch}",
            params={"recursive": "1"},
        )

    tree = tree_data.get("tree", [])
    truncated = tree_data.get("truncated", False)

    # All files (blobs) in the repo — no filter applied
    all_blobs = [item for item in tree if item.get("type") == "blob"]
    total_files = len(all_blobs)

    # Files that match our extension + size + skip filters
    candidates = [
        item for item in all_blobs
        if not _should_skip(item.get("path", ""))
        and _extension(item.get("path", "")) in ALLOWED_EXTENSIONS
        and item.get("size", 0) <= MAX_FILE_BYTES
    ][:MAX_FILES]

    # Files skipped due to extension (for reporting)
    skipped_ext = [
        item["path"] for item in all_blobs
        if not _should_skip(item.get("path", ""))
        and _extension(item.get("path", "")) not in ALLOWED_EXTENSIONS
    ]
    # Files skipped due to size
    skipped_size = [
        item["path"] for item in all_blobs
        if not _should_skip(item.get("path", ""))
        and item.get("size", 0) > MAX_FILE_BYTES
    ]

    findings = []
    files_scanned = 0
    scanned_list = []
    total_bytes = 0

    for item in candidates:
        if total_bytes >= MAX_TOTAL_BYTES:
            break
        path = item["path"]
        try:
            # Use raw.githubusercontent.com — no API rate limit!
            raw_url = f"https://raw.githubusercontent.com/{owner}/{repo}/{branch}/{path}"
            token = os.getenv("GITHUB_TOKEN", "")
            headers = {"User-Agent": "RepoRescueAI-Hackathon-MVP"}
            if token:
                headers["Authorization"] = f"Bearer {token}"
            resp = requests.get(raw_url, headers=headers, timeout=TIMEOUT)
            if resp.status_code != 200:
                continue
            raw = resp.content
            if len(raw) > MAX_FILE_BYTES:
                continue
            total_bytes += len(raw)
            content = raw.decode("utf-8", errors="replace")
            files_scanned += 1
            scanned_list.append(path)
            findings.extend(_findings_for_file(path, content))
        except (requests.RequestException, ValueError, KeyError):
            continue

    severity_order = {"High": 0, "Medium": 1, "Low": 2}
    findings.sort(key=lambda f: (severity_order.get(f["severity"], 9), f["path"], f["line"]))

    return {
        "full_name": full_name,
        "branch": branch,
        "total_files": total_files,
        "files_scanned": files_scanned,
        "scanned_list": scanned_list,
        "skipped_ext": skipped_ext,
        "skipped_size": skipped_size,
        "tree_truncated": truncated,
        "findings": findings[:100],
    }
