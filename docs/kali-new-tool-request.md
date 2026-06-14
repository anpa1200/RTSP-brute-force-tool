# Kali Linux New Tool Request: RTSP Brute Force Tool

Use this text when submitting under **New Tool Requests** at
<https://bugs.kali.org/>. Set reproducibility to `N/A`, severity to `minor`,
and priority to `normal`.

## Summary

rtsp-brute-force-tool - RTSP credential-security assessment with vendor presets

## Description

[Name] - RTSP Brute Force Tool

[Version] - 3.0.0

[Homepage] - https://github.com/anpa1200/RTSP-brute-force-tool

[Download] - https://github.com/anpa1200/RTSP-brute-force-tool/releases/tag/v3.0.0

[Author] - Andrey Pautov

[Licence] - GNU General Public License v3.0

[Description] - A scriptable authorized RTSP credential-security assessment
tool. It supports presets for 25+ camera vendors, multiple stream paths,
configurable wordlists, parallel workers, rate limiting, dry runs, exit codes,
and JSON reports.

[Dependencies] - Python 3.9 or newer; no third-party runtime dependencies.

[Similar tools] - hydra, medusa, ncrack

[Activity] - Started in October 2024 and actively maintained. Version 3.0.0
adds vendor presets, robust CLI automation, tests, and package metadata.

[How to install] - Download the v3.0.0 source release and run
`python3 -m pip install .`. Debian/Kali package metadata is included in the
`debian/` directory.

[How to use] - List vendor presets with `rtsp-brute-force --list-vendors`.
Authorized dry-run example:
`rtsp-brute-force -u rtsp://192.0.2.10:554/ -V hikvision --vendor-defaults --dry-run`.

[Packaged] - Debian/Kali package metadata is included upstream and builds the
`rtsp-brute-force-tool` binary package.
