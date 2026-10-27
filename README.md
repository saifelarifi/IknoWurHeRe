# IknoWurHeRe

```text
 _____ _                     _ _ _ _      _    _         _____
|_   _| |                   | | | | |    | |  | |       |  __ \
  | | | | ___ __   ___  __ _| | | | |    | |  | |_ __   | |__) |
  | | | |/ / '_ \ / _ \/ _` | | | | |    | |  | | '__|  |  _  /
 _| |_|   <| | | | (_) | (_| |_|_|_|_|    \ \_/ /| |    | | \ \\
|_____|_|\_|_| |_|\___/ \__, (_|_|_|_)     \___/ |_|    |_|  \_\
                         __/ |
                        |___/
```

**IknoWurHeRe** is an async command-line tool for finding devices on an authorized local IPv4 network. It combines ICMP `ping` with active ARP discovery and shows results in a Rich terminal table.

> Scan only networks you own or have permission to inventory. The scan is limited to RFC 1918 private IPv4 ranges and at most 256 addresses.

## Features

- Discovers devices that reply to `ping` and devices that reply to ARP.
- Shows whether each device was discovered by `PING`, `ARP`, or both.
- Displays IP, MAC (when available), and reverse-DNS hostname (when available).
- Exports results as JSON or CSV.
- Uses bounded async ping requests; it does not scan ports.

ARP discovery uses Scapy and raw network sockets, so it may require elevated permissions. If ARP cannot run, the tool warns and continues with ping results. Some devices block ICMP, and MAC addresses may be unavailable when a device is off-subnet or the operating system cannot learn its neighbor entry.

## Requirements

- Python 3.10 or newer
- The system `ping` command (`iputils-ping` on Debian/Ubuntu)
- Linux, macOS, or Windows; Windows ARP discovery requires Npcap and an elevated terminal

## Install from a clone

```bash
git clone https://github.com/YOUR-USER/IknoWurHeRe.git
cd IknoWurHeRe
python -m venv .venv
# Linux/macOS
source .venv/bin/activate
# Windows PowerShell: .venv\Scripts\Activate.ps1
python -m pip install --upgrade pip
python -m pip install -e ".[dev]"
```

Replace `YOUR-USER` with your GitHub username. If you use `uv`, `uv sync --extra dev` installs the same dependencies.

## Run

```bash
iknowurhere 192.168.8.0/24
iknowurhere 192.168.8.0/24 --output report.json
iknowurhere 192.168.8.0/24 --output report.csv --timeout 1.2 --concurrency 48
```

The example subnet is only an example: use the CIDR for the network you are authorized to scan. On Linux, if active ARP reports a permissions notice, run the installed command with elevated privileges:

```bash
sudo "$(command -v iknowurhere)" 192.168.8.0/24
```

The application caps concurrency at 256 and rejects networks larger than 256 addresses. It accepts RFC 1918 ranges (`10.0.0.0/8`, `172.16.0.0/12`, and `192.168.0.0/16`).

## Run tests

```bash
python -m pytest -q
```

The tests mock network responses; they do not send probes to your LAN.

## Project layout

```text
src/iknowurhere/       CLI and discovery logic
tests/                 pytest suite
.github/workflows/     automated tests on pushes and pull requests
pyproject.toml         package metadata and dependencies
```

## License

MIT. See [LICENSE](LICENSE).
