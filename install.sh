#!/bin/bash
#══════════════════════════════════════════════════════════════════════════
#  POT — Professional Offensive Tool
#  Installer for Kali Linux
#  Run: sudo bash install.sh
#══════════════════════════════════════════════════════════════════════════

set -e

RESET='\033[0m'
BOLD='\033[1m'
DIM='\033[2m'
ITALIC='\033[3m'
BRED='\033[91m'
BGREEN='\033[92m'
BYELLOW='\033[93m'
BCYAN='\033[96m'
BWHITE='\033[97m'

INSTALL_DIR="$(cd "$(dirname "$0")" && pwd)"
GO_BIN="/usr/local/go/bin"
GOPATH_BIN="$HOME/go/bin"

timestamp() {
    date +"%Y-%m-%d %H:%M:%S"
}

info() {
    echo -e "[${BCYAN}$(timestamp)${RESET}] [${BCYAN}inf${RESET}] $1"
}

warn() {
    echo -e "[${BCYAN}$(timestamp)${RESET}] [${BYELLOW}wrn${RESET}] $1"
}

error() {
    echo -e "[${BCYAN}$(timestamp)${RESET}] [${BRED}err${RESET}] $1"
}

banner() {
    echo -e "${BCYAN}${BOLD}"
    echo -e "    ____  ____  ______"
    echo -e "   / __ \\/ __ \\/_  __/"
    echo -e "  / /_/ / / / / / /   "
    echo -e " / ____/ /_/ / / /    "
    echo -e "/_/    \\____/ /_/     "
    echo -e "${RESET}"
    echo -e "                  ${ITALIC}Discovery Before Exploitation - iceberg${RESET}"
    echo ""
    echo -e "    ${DIM}XMR: 8BQ91yxDC2ChBCefXJLXN1JjSeRar5xj2WdE2Td4BVFQbMAkjTb1NdWBXaYuGDyNaTD7ueQ99gfnbDFVH2zauYGr6uaEWeP${RESET}"
    echo ""
}

check_root() {
    if [ "$EUID" -ne 0 ]; then
        error "This installer must be run as root (sudo bash install.sh)"
        exit 1
    fi
}

# ─── Step 1: System packages ───
install_system_packages() {
    info "Installing system packages..."
    apt-get update -qq 2>/dev/null

    PACKAGES=(
        curl wget git python3 python3-pip python3-venv
        nmap masscan whois dnsutils
        openssl jq chromium
        libpcap-dev build-essential
        sslscan tor proxychains4
    )

    for pkg in "${PACKAGES[@]}"; do
        if dpkg -l "$pkg" &>/dev/null; then
            echo -e "[${BCYAN}$(timestamp)${RESET}] [${DIM}dbg${RESET}] $pkg already installed"
        else
            apt-get install -y -qq "$pkg" 2>/dev/null && info "Installed $pkg" || warn "Failed to install $pkg"
        fi
    done
}

# ─── Step 2: Go language ───
install_go() {
    if command -v go &>/dev/null; then
        GO_VER=$(go version | awk '{print $3}')
        info "Go already installed: $GO_VER"
    else
        info "Go not found — installing..."
        GO_VERSION="1.22.4"
        wget -q "https://go.dev/dl/go${GO_VERSION}.linux-amd64.tar.gz" -O /tmp/go.tar.gz
        rm -rf /usr/local/go
        tar -C /usr/local -xzf /tmp/go.tar.gz
        rm /tmp/go.tar.gz

        export PATH="$PATH:${GO_BIN}:${GOPATH_BIN}"
        if ! grep -q "usr/local/go/bin" /etc/profile; then
            echo 'export PATH=$PATH:/usr/local/go/bin:$HOME/go/bin' >> /etc/profile
        fi
        info "Go installed: $(go version | awk '{print $3}')"
    fi
    export PATH="$PATH:${GO_BIN}:${GOPATH_BIN}"
}

# ─── Step 3: Go-based tools ───
install_go_tools() {
    info "Installing Go-based tools..."
    
    declare -A GOTOOLS=(
        ["subfinder"]="github.com/projectdiscovery/subfinder/v2/cmd/subfinder@latest"
        ["httpx"]="github.com/projectdiscovery/httpx/cmd/httpx@latest"
        ["nuclei"]="github.com/projectdiscovery/nuclei/v3/cmd/nuclei@latest"
        ["dnsx"]="github.com/projectdiscovery/dnsx/cmd/dnsx@latest"
        ["naabu"]="github.com/projectdiscovery/naabu/v2/cmd/naabu@latest"
        ["katana"]="github.com/projectdiscovery/katana/cmd/katana@latest"
        ["chaos"]="github.com/projectdiscovery/chaos-client/cmd/chaos@latest"
        ["shuffledns"]="github.com/projectdiscovery/shuffledns/cmd/shuffledns@latest"
        ["assetfinder"]="github.com/tomnomnom/assetfinder@latest"
        ["waybackurls"]="github.com/tomnomnom/waybackurls@latest"
        ["httprobe"]="github.com/tomnomnom/httprobe@latest"
        ["gau"]="github.com/lc/gau/v2/cmd/gau@latest"
        ["ffuf"]="github.com/ffuf/ffuf/v2@latest"
        ["gospider"]="github.com/jaeles-project/gospider@latest"
        ["hakrawler"]="github.com/hakluke/hakrawler@latest"
        ["gobuster"]="github.com/OJ/gobuster/v3@latest"
        ["subjack"]="github.com/haccer/subjack@latest"
        ["gowitness"]="github.com/sensepost/gowitness@latest"
    )

    for tool in "${!GOTOOLS[@]}"; do
        if command -v "$tool" &>/dev/null; then
            echo -e "[${BCYAN}$(timestamp)${RESET}] [${DIM}dbg${RESET}] $tool already installed"
        else
            if go install "${GOTOOLS[$tool]}" 2>/dev/null; then
                info "$tool installed"
            else
                warn "Failed to install $tool (non-critical)"
            fi
        fi
    done

    if [ -d "$GOPATH_BIN" ]; then
        cp -n "$GOPATH_BIN"/* /usr/local/bin/ 2>/dev/null || true
    fi
    if [ -d "/root/go/bin" ]; then
        cp -n /root/go/bin/* /usr/local/bin/ 2>/dev/null || true
    fi
}

# ─── Step 4: Python-based tools ───
install_python_tools() {
    info "Installing Python-based tools..."

    PIP_TOOLS=("arjun" "dirsearch" "theHarvester" "paramspider" "wafw00f")

    for tool in "${PIP_TOOLS[@]}"; do
        if pip3 show "$tool" &>/dev/null || command -v "$tool" &>/dev/null; then
            echo -e "[${BCYAN}$(timestamp)${RESET}] [${DIM}dbg${RESET}] $tool already installed"
        else
            pip3 install "$tool" -q 2>/dev/null && info "$tool installed" || warn "Failed to install $tool"
        fi
    done

    if [ ! -d "/opt/LinkFinder" ]; then
        git clone -q https://github.com/GerbenJavworski/LinkFinder.git /opt/LinkFinder 2>/dev/null || true
        cd /opt/LinkFinder && pip3 install -r requirements.txt -q 2>/dev/null && cd - >/dev/null
        info "LinkFinder installed"
    else
        echo -e "[${BCYAN}$(timestamp)${RESET}] [${DIM}dbg${RESET}] LinkFinder already installed"
    fi

    if ! command -v findomain &>/dev/null; then
        wget -q "https://github.com/Findomain/Findomain/releases/latest/download/findomain-linux.zip" -O /tmp/findomain.zip 2>/dev/null
        if [ -f /tmp/findomain.zip ]; then
            unzip -qo /tmp/findomain.zip -d /tmp/ 2>/dev/null
            chmod +x /tmp/findomain 2>/dev/null
            mv /tmp/findomain /usr/local/bin/ 2>/dev/null
            rm -f /tmp/findomain.zip
            info "findomain installed"
        else
            warn "Failed to download findomain"
        fi
    else
        echo -e "[${BCYAN}$(timestamp)${RESET}] [${DIM}dbg${RESET}] findomain already installed"
    fi

    # Apt tools
    for tool in amass massdns dnsrecon testssl.sh whatweb; do
        if ! command -v "$tool" &>/dev/null; then
            apt-get install -y -qq "$tool" 2>/dev/null && info "$tool installed" || warn "Failed to install $tool"
        else
            echo -e "[${BCYAN}$(timestamp)${RESET}] [${DIM}dbg${RESET}] $tool already installed"
        fi
    done
}

# ─── Step 5: Wordlists & Templates ───
install_wordlists() {
    info "Setting up wordlists and templates..."

    if [ ! -d "/usr/share/seclists" ] && [ ! -d "/opt/seclists" ]; then
        apt-get install -y -qq seclists 2>/dev/null && info "SecLists installed" || {
            git clone -q --depth 1 https://github.com/danielmiessler/SecLists.git /opt/seclists 2>/dev/null
            info "SecLists cloned to /opt/seclists"
        }
    else
        echo -e "[${BCYAN}$(timestamp)${RESET}] [${DIM}dbg${RESET}] SecLists already installed"
    fi

    if command -v nuclei &>/dev/null; then
        nuclei -update-templates -silent 2>/dev/null && info "Nuclei templates updated" || warn "Template update failed"
    fi

    RESOLVERS="/opt/pot-resolvers.txt"
    if [ ! -f "$RESOLVERS" ]; then
        cat > "$RESOLVERS" << 'EOF'
8.8.8.8
8.8.4.4
1.1.1.1
1.0.0.1
9.9.9.9
149.112.112.112
208.67.222.222
208.67.220.220
64.6.64.6
64.6.65.6
185.228.168.9
185.228.169.9
76.76.19.19
76.223.122.150
94.140.14.14
94.140.15.15
EOF
        info "DNS resolvers created at $RESOLVERS"
    else
        echo -e "[${BCYAN}$(timestamp)${RESET}] [${DIM}dbg${RESET}] DNS resolvers file exists"
    fi
}

# ─── Step 6: Install POT ───
install_pot() {
    info "Linking POT to /usr/local/bin/pot..."
    chmod +x "${INSTALL_DIR}/pot"
    ln -sf "${INSTALL_DIR}/pot" /usr/local/bin/pot
    
    if command -v pot &>/dev/null; then
        info "POT installed successfully"
    else
        error "Symlink failed. Run directly: sudo ${INSTALL_DIR}/pot"
    fi
}

# ═══════════════════════════════════════════════════════════════════════════
#  MAIN
# ═══════════════════════════════════════════════════════════════════════════

main() {
    banner
    check_root
    info "Starting installation in ${INSTALL_DIR}"

    install_system_packages
    install_go
    install_go_tools
    install_python_tools
    install_wordlists
    install_pot

    info "Installation Complete!"
    info "Usage: sudo pot https://target.com"
}

main "$@"
