#!/usr/bin/env bash
# ==============================================================================
# SIH26106: AI-Powered Email Threat Detection, GeoLocation & Forensics Platform
# Unified Platform Orchestrator (Backend + SOC Dashboard + DB Seeder)
# ==============================================================================

set -e

DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
cd "$DIR"

# Colors for terminal styling
CYAN='\033[0;36m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
RED='\033[0;31m'
BOLD='\033[1m'
NC='\033[0m' # No Color

echo -e "${CYAN}${BOLD}"
echo "╔═══════════════════════════════════════════════════════════════════════╗"
echo "║      SIH26106: FORENSIC INTELLIGENCE & THREAT PLATFORM               ║"
echo "║          AI-Powered Email Detection, GeoLocation & Forensics          ║"
echo "╚═══════════════════════════════════════════════════════════════════════╝"
echo -e "${NC}"

# 1. Resolve Python Interpreter
if [ -f "/home/aspartic/venvs/ml/bin/python3" ]; then
    PYTHON="/home/aspartic/venvs/ml/bin/python3"
elif [ -n "$VIRTUAL_ENV" ]; then
    PYTHON="$VIRTUAL_ENV/bin/python3"
else
    PYTHON="python3"
fi
echo -e "${GREEN}✓ Using Python:${NC} $($PYTHON --version) ($PYTHON)"

# 2. Check Node.js
if command -v node >/dev/null 2>&1; then
    echo -e "${GREEN}✓ Using Node.js:${NC} $(node -v)"
else
    echo -e "${RED}✗ Error: Node.js is not installed!${NC}"
    exit 1
fi

# 3. Clean up any existing instances on ports 8005 and 3001
echo -e "${YELLOW}⚡ Checking and clearing occupied ports...${NC}"
fuser -k 8005/tcp >/dev/null 2>&1 || true
fuser -k 3001/tcp >/dev/null 2>&1 || true
sleep 1

# 4. Verify / Seed Database with Forensic Threats & Campaigns
echo -e "${YELLOW}⚡ Seeding database with realistic threat vectors and campaigns...${NC}"
$PYTHON seed_email_forensics.py >/dev/null 2>&1
echo -e "${GREEN}✓ Forensic intelligence database seeded successfully.${NC}"

# 5. Start Backend Server
echo -e "${YELLOW}⚡ Starting FastAPI Backend on port 8005...${NC}"
$PYTHON start_server.py > backend.log 2>&1 &
BACKEND_PID=$!

# Wait for backend to be healthy
echo -n "   Waiting for Backend API to respond"
for i in {1..20}; do
    if [ "$(curl -s -o /dev/null -w "%{http_code}" http://127.0.0.1:8005/health 2>/dev/null)" = "200" ]; then
        echo -e " ${GREEN}[READY]${NC}"
        break
    fi
    echo -n "."
    sleep 0.5
done

# 6. Start SOC Analyst Dashboard
echo -e "${YELLOW}⚡ Starting Next.js SOC Dashboard on port 3001...${NC}"
cd "$DIR/dashboard"
npm run dev > ../dashboard.log 2>&1 &
DASHBOARD_PID=$!
cd "$DIR"

# Wait for dashboard port
echo -n "   Waiting for SOC Dashboard to respond"
for i in {1..20}; do
    if curl -s http://127.0.0.1:3001/ >/dev/null 2>&1; then
        echo -e " ${GREEN}[READY]${NC}"
        break
    fi
    echo -n "."
    sleep 0.5
done

echo ""
echo -e "${GREEN}${BOLD}═══════════════════════════════════════════════════════════════════════${NC}"
echo -e "${GREEN}${BOLD}             PLATFORM SUCCESSFULLY LAUNCHED AND LIVE!                  ${NC}"
echo -e "${GREEN}${BOLD}═══════════════════════════════════════════════════════════════════════${NC}"
echo -e "  ${BOLD}• SOC Analyst Dashboard:${NC}      ${CYAN}http://localhost:3001${NC}"
echo -e "  ${BOLD}• Live Gmail Threat Feed:${NC}     ${CYAN}http://localhost:3001/gmail${NC}"
echo -e "  ${BOLD}• Backend API & Docs:${NC}         ${CYAN}http://localhost:8005/docs${NC}"
echo -e "  ${BOLD}• Chrome Extension:${NC}           ${YELLOW}Load unpacked './extension-final'${NC}"
echo -e "  ${BOLD}• Logs:${NC}                       ${YELLOW}backend.log, dashboard.log${NC}"
echo -e "${GREEN}${BOLD}═══════════════════════════════════════════════════════════════════════${NC}"
echo -e "${YELLOW}Press [Ctrl+C] at any time to cleanly shut down all platform services.${NC}"
echo ""

# Graceful shutdown handler
cleanup() {
    echo ""
    echo -e "${YELLOW}🛑 Shutting down Forensic Intelligence Platform...${NC}"
    kill $BACKEND_PID 2>/dev/null || true
    kill $DASHBOARD_PID 2>/dev/null || true
    fuser -k 8005/tcp >/dev/null 2>&1 || true
    fuser -k 3001/tcp >/dev/null 2>&1 || true
    echo -e "${GREEN}✓ All services stopped cleanly. Goodbye!${NC}"
    exit 0
}

trap cleanup SIGINT SIGTERM

# Wait for background processes
wait $BACKEND_PID $DASHBOARD_PID
