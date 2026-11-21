# sdu-connect backend

Python backend for SDU VPN for Windows. It performs the CAS login, exchanges the
ticket with the campus aTrust gateway, and starts the local proxy data plane.

Everything the backend needs is in this folder:

- `sdu_connect/` — CAS, aTrust session, endpoint identity, proxy and SSH helpers,
  plus the `pywebview` desktop shell (`app.py`) and its web UI (`webui/`).
- `bin/zju-connect.exe` — the local SOCKS5 / HTTP proxy data plane (Windows amd64).
  It is **not** kept in this repository: `windows\install.ps1` downloads the
  upstream [zju-connect](https://github.com/Mythologyli/zju-connect) v1.3.1 release
  (AGPL-3.0) and verifies its SHA-256. SOCKS5 and HTTP listen on `127.0.0.1:1080`
  and `127.0.0.1:1081` by default.
- `tests/` — unit tests that never touch a real account (`python -m unittest discover -s tests`).
- `pyproject.toml` — package metadata and dependencies.

Cookies, session data, endpoint identity, logs and proxy snapshots are written
outside this source tree (`%APPDATA%\sdu-connect` on Windows, or `SDU_CONNECT_HOME`).
Never commit those runtime files.
