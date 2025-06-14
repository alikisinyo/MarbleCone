#!/bin/bash

# MarbleCone Linux Agent Script
# This script creates a persistent agent that connects to the MarbleCone threat emulator
# and executes threat emulation tasks

set -e

# Configuration
SERVER_URL="${MARBLECONE_SERVER:-http://localhost:5000}"
AGENT_NAME="linux-agent-$(hostname)-$(date +%s)"
AGENT_PAW="$(uuidgen)"
PLATFORM="linux"
HOST_IP="$(hostname -I | awk '{print $1}')"
WORK_DIR="/tmp/.marblecone"
LOG_FILE="$WORK_DIR/agent.log"
PID_FILE="$WORK_DIR/agent.pid"

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

# Logging function
log() {
    echo -e "${GREEN}[$(date '+%Y-%m-%d %H:%M:%S')]${NC} $1" | tee -a "$LOG_FILE"
}

error() {
    echo -e "${RED}[$(date '+%Y-%m-%d %H:%M:%S')] ERROR:${NC} $1" | tee -a "$LOG_FILE"
}

warn() {
    echo -e "${YELLOW}[$(date '+%Y-%m-%d %H:%M:%S')] WARNING:${NC} $1" | tee -a "$LOG_FILE"
}

info() {
    echo -e "${BLUE}[$(date '+%Y-%m-%d %H:%M:%S')] INFO:${NC} $1" | tee -a "$LOG_FILE"
}

# Check if running as root
check_root() {
    if [[ $EUID -eq 0 ]]; then
        warn "Running as root - this agent will have elevated privileges"
    fi
}

# Create working directory
setup_environment() {
    log "Setting up MarbleCone agent environment..."
    
    # Create working directory
    mkdir -p "$WORK_DIR"
    
    # Create log file
    touch "$LOG_FILE"
    
    # Set permissions
    chmod 700 "$WORK_DIR"
    chmod 600 "$LOG_FILE"
    
    log "Working directory: $WORK_DIR"
    log "Log file: $LOG_FILE"
}

# Check dependencies
check_dependencies() {
    log "Checking system dependencies..."
    
    local missing_deps=()
    
    # Check for curl
    if ! command -v curl &> /dev/null; then
        missing_deps+=("curl")
    fi
    
    # Check for jq
    if ! command -v jq &> /dev/null; then
        missing_deps+=("jq")
    fi
    
    # Check for uuidgen
    if ! command -v uuidgen &> /dev/null; then
        missing_deps+=("uuid-runtime")
    fi
    
    if [[ ${#missing_deps[@]} -gt 0 ]]; then
        error "Missing dependencies: ${missing_deps[*]}"
        info "Installing missing dependencies..."
        
        if command -v apt-get &> /dev/null; then
            sudo apt-get update && sudo apt-get install -y "${missing_deps[@]}"
        elif command -v yum &> /dev/null; then
            sudo yum install -y "${missing_deps[@]}"
        elif command -v dnf &> /dev/null; then
            sudo dnf install -y "${missing_deps[@]}"
        else
            error "Could not install dependencies automatically. Please install: ${missing_deps[*]}"
            exit 1
        fi
    fi
    
    log "All dependencies satisfied"
}

# Register agent with server
register_agent() {
    log "Registering agent with MarbleCone server..."
    
    local agent_data=$(cat <<EOF
{
    "name": "$AGENT_NAME",
    "paw": "$AGENT_PAW",
    "platform": "$PLATFORM",
    "host": "$HOST_IP",
    "status": "active"
}
EOF
)
    
    local response=$(curl -s -w "%{http_code}" -X POST \
        -H "Content-Type: application/json" \
        -d "$agent_data" \
        "$SERVER_URL/api/agents")
    
    local http_code="${response: -3}"
    local body="${response%???}"
    
    if [[ "$http_code" == "200" ]]; then
        log "Agent registered successfully"
        echo "$AGENT_PAW" > "$WORK_DIR/agent.paw"
        return 0
    else
        error "Failed to register agent. HTTP code: $http_code"
        error "Response: $body"
        return 1
    fi
}

# Execute command and capture output
execute_command() {
    local command="$1"
    local task_id="$2"
    
    echo "=== Task $task_id Execution ==="
    echo "Command: $command"
    echo "Timestamp: $(date -Iseconds)"
    echo "User: $(whoami)"
    echo "Hostname: $(hostname)"
    echo "Working Directory: $(pwd)"
    echo ""
    
    # Execute command with timeout and capture output
    local output
    local exit_code
    
    # Use timeout to prevent hanging commands (30 seconds max)
    if timeout 30 bash -c "$command" 2>&1; then
        output=$(timeout 30 bash -c "$command" 2>&1)
        exit_code=$?
    else
        output="Command timed out after 30 seconds"
        exit_code=124
    fi
    
    echo ""
    echo "=== Task $task_id Completed ==="
    
    # Submit result to server
    submit_task_result "$task_id" "$output" "$exit_code"
}

# Submit task result to server
submit_task_result() {
    local task_id="$1"
    local output="$2"
    local exit_code="$3"
    
    # Escape the output for JSON (replace newlines, quotes, backslashes)
    local escaped_output=$(echo "$output" | sed 's/\\/\\\\/g' | sed 's/"/\\"/g' | sed ':a;N;$!ba;s/\n/\\n/g')
    
    local result_data=$(cat <<EOF
{
    "result": "$escaped_output",
    "exit_code": $exit_code,
    "timestamp": "$(date -Iseconds)"
}
EOF
)
    
    local response=$(curl -s -w "%{http_code}" -X POST \
        -H "Content-Type: application/json" \
        -d "$result_data" \
        "$SERVER_URL/api/tasks/$task_id/result")
    
    local http_code="${response: -3}"
    
    if [[ "$http_code" == "200" ]]; then
        log "Task result submitted successfully"
    else
        error "Failed to submit task result. HTTP code: $http_code"
        error "Response: $response"
    fi
}

# Poll for tasks
poll_tasks() {
    log "Polling for tasks..."
    
    local response=$(curl -s "$SERVER_URL/api/agents/$AGENT_PAW/tasks")
    
    if [[ $? -ne 0 ]]; then
        error "Failed to poll for tasks"
        return 1
    fi
    
    local tasks=$(echo "$response" | jq -r '.tasks[]? | @base64')
    
    if [[ -z "$tasks" ]]; then
        info "No pending tasks"
        return 0
    fi
    
    while IFS= read -r task; do
        if [[ -n "$task" ]]; then
            local task_data=$(echo "$task" | base64 -d)
            local task_id=$(echo "$task_data" | jq -r '.id')
            local command=$(echo "$task_data" | jq -r '.command')
            
            execute_command "$command" "$task_id"
        fi
    done <<< "$tasks"
    
    return 0
}

# Main agent loop
agent_loop() {
    log "Starting MarbleCone agent loop..."
    
    # Save PID
    echo $$ > "$PID_FILE"
    
    # Main loop
    while true; do
        if ! poll_tasks; then
            warn "Task polling failed, retrying in 30 seconds..."
            sleep 30
            continue
        fi
        
        # Wait before next poll
        sleep 10
    done
}

# Signal handlers
cleanup() {
    log "Shutting down MarbleCone agent..."
    rm -f "$PID_FILE"
    exit 0
}

trap cleanup SIGINT SIGTERM

# Check if agent is already running
check_running() {
    if [[ -f "$PID_FILE" ]]; then
        local pid=$(cat "$PID_FILE")
        if kill -0 "$pid" 2>/dev/null; then
            error "MarbleCone agent is already running (PID: $pid)"
            exit 1
        else
            warn "Stale PID file found, removing..."
            rm -f "$PID_FILE"
        fi
    fi
}

# Install as service
install_service() {
    log "Installing MarbleCone agent as systemd service..."
    
    local service_file="/etc/systemd/system/marblecone-agent.service"
    
    cat > "$service_file" <<EOF
[Unit]
Description=MarbleCone Threat Emulation Agent
After=network.target

[Service]
Type=simple
User=root
ExecStart=$0 --daemon
Restart=always
RestartSec=10
Environment=MARBLECONE_SERVER=$SERVER_URL

[Install]
WantedBy=multi-user.target
EOF
    
    systemctl daemon-reload
    systemctl enable marblecone-agent.service
    
    log "Service installed. Start with: systemctl start marblecone-agent"
}

# Uninstall service
uninstall_service() {
    log "Uninstalling MarbleCone agent service..."
    
    systemctl stop marblecone-agent.service 2>/dev/null || true
    systemctl disable marblecone-agent.service 2>/dev/null || true
    rm -f /etc/systemd/system/marblecone-agent.service
    systemctl daemon-reload
    
    log "Service uninstalled"
}

# Show status
show_status() {
    if [[ -f "$PID_FILE" ]]; then
        local pid=$(cat "$PID_FILE")
        if kill -0 "$pid" 2>/dev/null; then
            log "MarbleCone agent is running (PID: $pid)"
            log "Agent PAW: $AGENT_PAW"
            log "Server URL: $SERVER_URL"
            log "Log file: $LOG_FILE"
        else
            error "Agent PID file exists but process is not running"
        fi
    else
        error "MarbleCone agent is not running"
    fi
}

# Show help
show_help() {
    cat <<EOF
MarbleCone Linux Agent

Usage: $0 [OPTIONS]

Options:
    --daemon          Run in daemon mode (for systemd service)
    --install         Install as systemd service
    --uninstall       Uninstall systemd service
    --status          Show agent status
    --help            Show this help message

Environment Variables:
    MARBLECONE_SERVER    MarbleCone server URL (default: http://localhost:5000)

Examples:
    $0                    # Run agent interactively
    $0 --daemon          # Run agent in background
    $0 --install         # Install as system service
    $0 --status          # Check agent status

EOF
}

# Main function
main() {
    setup_environment
    case "${1:-}" in
        --daemon)
            # Run in daemon mode
            exec 1>/dev/null 2>/dev/null
            ;;
        --install)
            install_service
            exit 0
            ;;
        --uninstall)
            uninstall_service
            exit 0
            ;;
        --status)
            show_status
            exit 0
            ;;
        --help|-h)
            show_help
            exit 0
            ;;
        "")
            # Interactive mode
            ;;
        *)
            error "Unknown option: $1"
            show_help
            exit 1
            ;;
    esac
    
    # Banner
    cat <<EOF
${BLUE}
╔══════════════════════════════════════════════════════════════╗
║                    MarbleCone Linux Agent                    ║
║                Advanced Threat Emulation Agent               ║
╚══════════════════════════════════════════════════════════════╝
${NC}

Agent Name: $AGENT_NAME
Agent PAW:  $AGENT_PAW
Platform:   $PLATFORM
Host IP:    $HOST_IP
Server URL: $SERVER_URL

${YELLOW}WARNING: This agent is designed for threat emulation and testing purposes only.
Do not use on production systems without proper authorization.${NC}

EOF
    
    # Initialize
    check_root
    check_dependencies
    check_running
    
    # Register and start
    if register_agent; then
        agent_loop
    else
        error "Failed to register agent. Exiting..."
        exit 1
    fi
}

# Run main function
main "$@" 