# RTSP Brute Force Tool

Production-grade utility for **authorized** security assessment of RTSP (Real Time Streaming Protocol) services. Supports **vendor presets** (Hikvision, Dahua, Axis, Hanwha, Uniview, and 20+ others), **multiple paths**, **wordlist directories**, **config files**, parallel workers, and a scriptable CLI.

**Use only on systems you are authorized to test. Unauthorized access is illegal.**

---

## Features

- **Vendor presets** — Built-in stream paths and optional default credentials for 25+ vendors (Hikvision, Dahua, Axis, Hanwha, Uniview, Arecont, Pelco, Vivotek, ACTi, Swann, Amcrest, Lorex, Foscam, Reolink, and more)
- **Multiple targets** — One base URL + many paths (from `--path`, `--path-file`, or `--vendor`)
- **Wordlist directory** — Optional `wordlists/vendors/<vendor>/users.txt`, `passwords.txt`, `paths.txt` override or extend built-in lists
- **Config file** — JSON config via `--config`; CLI options override file
- **CLI & interactive** — Full argparse CLI and optional interactive prompts
- **Parallel workers** — Configurable thread pool, rate limiting, retries, shuffle
- **Output** — Exit codes, credential file, JSON report; `--dry-run`, `--no-banner`

---

## Requirements

- **Python 3.9+** (no third-party dependencies)
- Optional: `wordlists/` directory with vendor subdirs (see [Wordlists](#wordlists))

---

## Installation

```bash
git clone https://github.com/yourusername/RTSP-brute-force-tool.git
cd RTSP-brute-force-tool
```

Optional virtual environment:

```bash
python3 -m venv .venv
source .venv/bin/activate   # Linux/macOS
```

---

## Usage

### Interactive mode (no arguments)

```bash
python3 ./RTSP_bruteforce.py
```

### Command-line (scriptable)

```bash
python3 ./RTSP_bruteforce.py --url <BASE_RTSP_URL> [OPTIONS]
```

**Target (required unless interactive):**

- `--url`, `-u` — Base RTSP URL (e.g. `rtsp://192.168.1.1:554/`)
- `--path`, `-p` — RTSP path to try (repeatable); no leading slash
- `--path-file` — File with one RTSP path per line
- `--vendor`, `-V` — Vendor preset name (repeatable): tries built-in paths for that vendor
- `--vendor-defaults` — With `--vendor`: use vendor default usernames/passwords if you do not pass `--users`/`--passwords`

**Credentials:**

- `--users`, `-U` — Comma-separated usernames
- `--user-file` — One username per line
- `--passwords`, `-P` — Comma-separated passwords
- `--password-file`, `-F` — Password list file

**Performance & behavior:**

- `--workers`, `-w` — Parallel workers (default: 4)
- `--timeout`, `-t` — Connection timeout (s)
- `--extended-timeout` — Timeout after first timeout (s)
- `--retries`, `-r` — Retries per credential
- `--delay`, `-d` — Delay between attempts per worker (s)
- `--shuffle`, `-s` — Randomize order of attempts
- `--all`, `-a` — Report every valid credential (do not stop on first)
- `--user-agent` — RTSP User-Agent header

**Output:**

- `--output`, `-o` — Write found credentials (URL + user:pass per line)
- `--json`, `-j` — JSON report file

**Wordlists & config:**

- `--wordlist-dir`, `-W` — Wordlist root (default: `wordlists/` next to script); vendor files under `vendors/<name>/`
- `--config`, `-c` — JSON config file (CLI overrides file)

**Info (exit without attacking):**

- `--list-vendors` — List built-in vendor names
- `--list-paths VENDOR` — List built-in paths for that vendor

**Logging & UX:**

- `--log-file` — Append logs to file
- `--verbose`, `-v` — DEBUG logging
- `--quiet`, `-q` — Minimal console output
- `--no-banner` — Do not print banner
- `--dry-run` — Print targets and task count, then exit

---

## Wordlists

Optional directory layout (under `--wordlist-dir`, default `wordlists/`):

- `wordlists/vendors/<vendor_name>/users.txt` — one username per line
- `wordlists/vendors/<vendor_name>/passwords.txt` — one password per line
- `wordlists/vendors/<vendor_name>/paths.txt` — one RTSP path per line (no leading slash)

If these exist, they are used instead of (or for paths, in addition to) built-in vendor data. See `wordlists/vendors/README.md`.

---

## Examples

**Single URL, custom credentials:**

```bash
python3 ./RTSP_bruteforce.py --url rtsp://192.168.1.143:554/media.sdp \
  --users admin --password-file ./passwords.txt
```

**Hikvision preset: built-in paths + vendor default users/passwords:**

```bash
python3 ./RTSP_bruteforce.py -u rtsp://192.168.1.1:554/ --vendor hikvision --vendor-defaults
```

**Multiple vendors, custom wordlist dir, dry-run:**

```bash
python3 ./RTSP_bruteforce.py -u rtsp://10.0.0.1:554/ -V hikvision -V dahua --vendor-defaults \
  -W ./wordlists --dry-run
```

**Custom paths from file, 8 workers, output files:**

```bash
python3 ./RTSP_bruteforce.py -u rtsp://camera.local:554/ --path-file my_paths.txt \
  -U admin,root -F pw.txt -w 8 -o found.txt -j report.json
```

**Config file (options in JSON):**

```bash
python3 ./RTSP_bruteforce.py -c config.example.json
```

**List vendors and paths:**

```bash
python3 ./RTSP_bruteforce.py --list-vendors
python3 ./RTSP_bruteforce.py --list-paths hikvision
```

**Quiet, shuffle, no banner (scripting):**

```bash
python3 ./RTSP_bruteforce.py -q --no-banner -u rtsp://host:554/ -V dahua --vendor-defaults -o creds.txt
```

---

## Exit codes

- **0** — At least one valid credential found
- **1** — No valid credential found
- **2** — Usage or configuration error

---

## License

GNU General Public License v3. See [LICENSE](LICENSE).

---

## Disclaimer

This tool is for **educational and authorized security testing only**. Use only on systems you have explicit permission to test. The developers assume no liability for misuse.
