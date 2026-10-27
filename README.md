# IknoWurHeRe

```text
 _____ _                     _ _ _ _      _    _         _____
|_   _| |                   | | | | |    | |  | |       |  __ \
  | | | | ___ __   ___  __ _| | | | |    | |  | |_ __   | |__) |
  | | | |/ / '_ \ / _ \/ _` | | | | |    | |  | | '__|  |  _  /
 _| |_|   <| | | | (_) | (_| |_|_|_|_|    \ \_/ /| |    | | \\
|_____|_|\_|_| |_|\___/ \__, (_|_|_|_)     \___/ |_|    |_|  \_\
                         __/ |
                        |___/
```

**IknoWurHeRe** is a defensive local-network inventory and change-monitoring tool. It discovers devices with ICMP ping and ARP, stores sightings in SQLite, detects infrastructure changes, and provides a Rich CLI plus a local web dashboard.

## Screenshots / UI Preview

The screenshots directory is [`docs/screenshots/`](docs/screenshots/). Add sanitized desktop and mobile captures there, then enable the image links below. The dashboard preview should show its black background with neon pink and cyan accents. Blur or remove real IP, MAC, hostname, and access-token data before committing images.

<!-- Screenshot placeholder: save a sanitized dashboard image as docs/screenshots/dashboard.png, then enable the next line.
![IknoWurHeRe cyberpunk dashboard](docs/screenshots/dashboard.png)
-->

<!-- Screenshot placeholder: save a sanitized mobile view as docs/screenshots/dashboard-mobile.png, then enable the next line.
![IknoWurHeRe mobile dashboard](docs/screenshots/dashboard-mobile.png)
-->

> Use it only on networks you own or are authorized to monitor. Scanning is limited to RFC 1918 IPv4 networks of at most 256 addresses. The passive monitor records ARP identity and DHCP server metadata only; it does not capture web traffic, page contents, or credentials.

## Capabilities

- `scan`: perform an authorized inventory scan and persist device history.
- `watch`: repeat scans while passively observing ARP replies and DHCP offers on a selected interface.
- `devices` and `alerts`: inspect saved history, first/last seen timestamps, reasons, and confidence scores.
- `interfaces`: list capture interfaces and mark the interface used by the default route.
- `export`: export historical devices or alerts as JSON or CSV.
- `web`: serve a responsive FastAPI dashboard with device inventory, gateway/DNS state, alerts, and automatic refresh.
- Detect new devices, changed IP-to-MAC mappings, gateway MAC/IP changes, DNS changes, and DHCP servers outside an optional allowlist.
- Optional offline vendor names from an IEEE-style OUI CSV file.
- GitHub Actions tests run on Linux, macOS, and Windows.

An alert describes an observed change, not proof of an attack. Router replacement, DHCP changes, and MAC randomization can be legitimate. Passive packet visibility depends on the selected interface, OS capture permissions, switch/AP behavior, and Npcap/libpcap support.

## Requirements and installation

- Python 3.10 or newer
- System `ping` command (`iputils-ping` on Linux)
- Scapy capture support for passive ARP/DHCP monitoring; Windows requires Npcap

```bash
git clone https://github.com/saifelarifi/IknoWurHeRe.git
cd IknoWurHeRe
python -m venv .venv
# Linux/macOS
source .venv/bin/activate
# Windows PowerShell: .venv\Scripts\Activate.ps1
python -m pip install --upgrade pip
python -m pip install -e ".[dev]"
```

The examples below use `192.168.8.0/24`; replace it with the authorized subnet you intend to inventory.

## CLI

```bash
# One scan; store devices, gateway, and DNS history
iknowurhere scan 192.168.8.0/24

# View saved inventory and alerts
iknowurhere devices
iknowurhere alerts --limit 100
iknowurhere interfaces

# Continuous scan and passive ARP/DHCP monitor
iknowurhere watch 192.168.8.0/24 --interface wlp4s0 --interval 60 \
  --trusted-dhcp 192.168.8.1 --trusted-gateway 192.168.8.1 \
  --trusted-dns 192.168.8.1,1.1.1.1

# Export complete history
iknowurhere export devices.json --kind devices
iknowurhere export alerts.csv --kind alerts
iknowurhere export network-state.json --kind network-state
```

Passive capture can require elevated capture permissions. If capture cannot start, `watch` explains the problem and continues its periodic inventory scans. `--trusted-*` options are optional allowlists; without them, the first observed value establishes a baseline and later changes create alerts.

## Web dashboard

Start the HTTPS dashboard on the same computer or make it available on the LAN:

```bash
iknowurhere web 192.168.8.0/24 --host 0.0.0.0 --port 8787 --interface wlp4s0
```

The command generates a strong random access token and a persistent self-signed TLS certificate automatically. It prints the token and the available HTTPS addresses. The dashboard performs scans every 60 seconds by default; its page refreshes every five seconds and includes a **Scan now** button, device search, and Recent/Stale filters. It also supports alert acknowledgement, a bounded quick check of common TCP ports for inventoried devices, and an HTML report download. The **PDF** action uses the browser's print dialog; choose “Save as PDF”.

On the computer running the tool, open `https://127.0.0.1:8787`. On another device connected to the same LAN, open the printed LAN URL, for example `https://192.168.8.102:8787`, then enter the token printed in the terminal. Allow inbound TCP port 8787 in the host firewall if needed. Use a trusted private LAN and do not share the token.

The auto-generated certificate encrypts traffic, but it is self-signed, so browsers will show an identity warning until you manually trust/import that certificate on each client device. HTTPS alone cannot make browsers trust a self-signed identity automatically. For a warning-free setup, supply a certificate issued by a CA trusted by the client devices:

```bash
iknowurhere web 192.168.8.0/24 --host 0.0.0.0 --port 8787 \
  --ssl-certfile /path/to/dashboard.crt --ssl-keyfile /path/to/dashboard.key
```

The certificate and private key are saved under the user's application-data directory in `iknowurhere/tls/`; on POSIX systems the key is mode `0600`. The dashboard requires its generated or supplied token for every API request, including manual scans and alert acknowledgement. The common-port check only attempts TCP connections to a fixed list of ports on a device already in the current inventory; it sends no application data. Passive ARP/DHCP capture may need elevated capture permissions; if unavailable, the dashboard and periodic active inventory continue.

### Optional traffic counters and notifications

Traffic counters are disabled by default. Enable them explicitly with `--traffic`:

```bash
iknowurhere web 192.168.8.0/24 --host 0.0.0.0 --port 8787 \
  --interface wlp4s0 --traffic
```

When enabled, the passive monitor keeps per-IP IPv4 header byte totals in memory only. It does not save packet contents, and the counters reset when the process exits. These are best-effort observations from the selected interface, not a router-level measurement: Wi-Fi client isolation, switched network visibility, and capture permissions can hide traffic.

Notifications are also optional and send alert summaries outbound only. Configure Discord with `IKNOWURHERE_DISCORD_WEBHOOK`, or Telegram with both `IKNOWURHERE_TELEGRAM_BOT_TOKEN` and `IKNOWURHERE_TELEGRAM_CHAT_ID`. Leave these unset to keep alerts local. Do not commit webhook URLs or bot tokens to the repository.

## OUI vendor names

Vendor lookup is offline and optional. Place an IEEE-style CSV registry containing `Assignment` and `Organization Name` columns at:

- Linux: `~/.local/share/iknowurhere/oui.csv` (or `$XDG_DATA_HOME/iknowurhere/oui.csv`)
- macOS: `~/Library/Application Support/IknoWurHeRe/oui.csv`
- Windows: `%LOCALAPPDATA%\IknoWurHeRe\oui.csv`

Alternatively set `IKNOWURHERE_OUI_FILE` to the CSV path. Without a registry, vendor is shown as unavailable.

## Database and reports

The SQLite database is stored in the platform's per-user application-data directory. It keeps observations scoped by subnet and preserves older `v0.1.0` device and alert data during migration. Fields include IP, MAC, hostname, source, optional vendor, first/last seen, alert reason, confidence, previous/current values, gateway, DNS, and observed DHCP server. Historical devices are labeled `recent` when seen in the last five minutes, otherwise `stale`; this is an inventory freshness marker, not a reachability guarantee.

## Tests

```bash
python -m pytest -q
```

Unit tests simulate ARP replies, DHCP offers, gateway/DNS changes, database migration, and dashboard API access. They do not scan a real network or send packets.

## Project layout

```text
src/iknowurhere/                 Python package (CLI, scanner, SQLite, monitor, web UI)
tests/                           Offline unit and API tests
docs/screenshots/                Sanitized project screenshots
.github/workflows/test.yml       Cross-platform GitHub Actions tests
```

## License

MIT. See [LICENSE](LICENSE).
