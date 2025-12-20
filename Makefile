.PHONY: all build build-frontend build-backend build-mcp run run-mcp dev test clean check-deps install-tshark install-npm ensure-tshark ensure-npm ensure-deps kill install-mcp mcp-config mcp-config-claude mcp-config-cursor

# Detect OS
UNAME_S := $(shell uname -s)

# Default target
all: build

# Build everything
build: ensure-deps build-frontend build-backend

# Build frontend
build-frontend: ensure-npm
	@echo "Building frontend..."
	cd web && npm install && npm run build

# Build backend
build-backend:
	@echo "Building backend..."
	go build -o uepcap ./cmd/server

# Build MCP server
build-mcp:
	@echo "Building MCP server..."
	go build -o uepcap-mcp ./cmd/mcp

# Install Node.js and npm based on platform
install-npm:
	@echo "Installing Node.js and npm..."
ifeq ($(UNAME_S),Darwin)
	@echo "Detected macOS, using Homebrew..."
	@which brew > /dev/null || (echo "Error: Homebrew not found. Please install Homebrew first: https://brew.sh" && exit 1)
	brew install node
else ifeq ($(UNAME_S),Linux)
	@if [ -f /etc/debian_version ]; then \
		echo "Detected Debian/Ubuntu, using apt-get..."; \
		sudo apt-get update && sudo apt-get install -y nodejs npm; \
	elif [ -f /etc/redhat-release ]; then \
		echo "Detected RHEL/CentOS/Fedora, using dnf/yum..."; \
		if which dnf > /dev/null 2>&1; then \
			sudo dnf install -y nodejs npm; \
		else \
			sudo yum install -y nodejs npm; \
		fi; \
	elif [ -f /etc/arch-release ]; then \
		echo "Detected Arch Linux, using pacman..."; \
		sudo pacman -S --noconfirm nodejs npm; \
	elif [ -f /etc/alpine-release ]; then \
		echo "Detected Alpine Linux, using apk..."; \
		sudo apk add --no-cache nodejs npm; \
	else \
		echo "Error: Unsupported Linux distribution. Please install Node.js and npm manually."; \
		exit 1; \
	fi
else
	@echo "Error: Unsupported OS ($(UNAME_S)). Please install Node.js and npm manually."
	@exit 1
endif
	@echo "Node.js and npm installed successfully!"

# Install tshark based on platform
install-tshark:
	@echo "Installing tshark..."
ifeq ($(UNAME_S),Darwin)
	@echo "Detected macOS, using Homebrew..."
	@which brew > /dev/null || (echo "Error: Homebrew not found. Please install Homebrew first: https://brew.sh" && exit 1)
	brew install wireshark
else ifeq ($(UNAME_S),Linux)
	@if [ -f /etc/debian_version ]; then \
		echo "Detected Debian/Ubuntu, using apt-get..."; \
		sudo apt-get update && sudo apt-get install -y tshark; \
	elif [ -f /etc/redhat-release ]; then \
		echo "Detected RHEL/CentOS/Fedora, using dnf/yum..."; \
		if which dnf > /dev/null 2>&1; then \
			sudo dnf install -y wireshark-cli; \
		else \
			sudo yum install -y wireshark; \
		fi; \
	elif [ -f /etc/arch-release ]; then \
		echo "Detected Arch Linux, using pacman..."; \
		sudo pacman -S --noconfirm wireshark-cli; \
	elif [ -f /etc/alpine-release ]; then \
		echo "Detected Alpine Linux, using apk..."; \
		sudo apk add --no-cache tshark; \
	else \
		echo "Error: Unsupported Linux distribution. Please install tshark manually."; \
		exit 1; \
	fi
else
	@echo "Error: Unsupported OS ($(UNAME_S)). Please install tshark manually."
	@exit 1
endif
	@echo "tshark installed successfully!"

# Check and install npm if needed
ensure-npm:
	@which npm > /dev/null 2>&1 || $(MAKE) install-npm

# Check and install tshark if needed
ensure-tshark:
	@which tshark > /dev/null 2>&1 || $(MAKE) install-tshark

# Ensure all dependencies
ensure-deps: ensure-tshark ensure-npm

# Run production server (with dependency check)
run: ensure-deps build
	./uepcap -port 8080

# Run MCP server (stdio transport, for AI clients)
run-mcp: ensure-tshark build-mcp
	./uepcap-mcp

# Run in development mode (requires two terminals)
dev: ensure-deps
	@echo "Starting backend..."
	@echo "Run 'cd web && npm run dev' in another terminal for frontend"
	go run ./cmd/server -port 8080

# Run tests
test:
	go test ./... -v

# Kill running uepcap process
kill:
	@echo "Stopping uepcap..."
ifeq ($(UNAME_S),Darwin)
	@pkill -f './uepcap' 2>/dev/null || pkill -f 'uepcap -port' 2>/dev/null || pkill -f 'go run ./cmd/server' 2>/dev/null || echo "No uepcap process found"
else ifeq ($(UNAME_S),Linux)
	@pkill -f './uepcap' 2>/dev/null || pkill -f 'uepcap -port' 2>/dev/null || pkill -f 'go run ./cmd/server' 2>/dev/null || echo "No uepcap process found"
else ifneq (,$(findstring MINGW,$(UNAME_S)))
	@taskkill /F /IM uepcap.exe 2>nul || echo "No uepcap process found"
else ifneq (,$(findstring MSYS,$(UNAME_S)))
	@taskkill /F /IM uepcap.exe 2>nul || echo "No uepcap process found"
else ifneq (,$(findstring CYGWIN,$(UNAME_S)))
	@taskkill /F /IM uepcap.exe 2>nul || echo "No uepcap process found"
else
	@echo "Warning: Unsupported OS ($(UNAME_S)). Trying pkill..."
	@pkill -f 'uepcap' 2>/dev/null || echo "No uepcap process found"
endif

# Clean build artifacts
clean:
	rm -f uepcap uepcap-mcp
	rm -rf cmd/server/dist
	rm -rf data/tmp/*
	cd web && rm -rf node_modules dist

# Check dependencies
check-deps:
	@which tshark > /dev/null || (echo "tshark not found. Run 'make install-tshark' to install." && exit 1)
	@which mergecap > /dev/null || (echo "mergecap not found. Run 'make install-tshark' to install." && exit 1)
	@which go > /dev/null || (echo "go not found. Please install Go 1.21+." && exit 1)
	@which npm > /dev/null || (echo "npm not found. Run 'make install-npm' to install." && exit 1)
	@which node > /dev/null || (echo "node not found. Run 'make install-npm' to install." && exit 1)
	@echo "All dependencies OK!"

# Install MCP server (build and show config)
install-mcp: ensure-tshark build-mcp
	@echo ""
	@echo "========================================"
	@echo "✅ MCP Server 安装完成!"
	@echo "========================================"
	@echo ""
	@echo "二进制文件: $(PWD)/uepcap-mcp"
	@echo "数据目录:   $(PWD)/data"
	@echo ""
	@echo "⚠️  重要: 配置时必须指定 --data-dir 参数指向数据目录"
	@echo "   这样 MCP 才能访问 Web 上传的 PCAP 文件"
	@echo ""
	@echo "运行 'make mcp-config' 查看配置示例"
	@echo ""

# Get absolute paths for MCP binary and data directory
MCP_PATH := $(shell pwd)/uepcap-mcp
DATA_DIR := $(shell pwd)/data

# Show MCP config for Claude Desktop
mcp-config-claude:
	@echo ""
	@echo "========================================"
	@echo "Claude Desktop 配置"
	@echo "========================================"
	@echo "配置文件路径:"
	@echo "  macOS: ~/Library/Application Support/Claude/claude_desktop_config.json"
	@echo "  Windows: %APPDATA%/Claude/claude_desktop_config.json"
	@echo ""
	@echo "添加以下内容到配置文件:"
	@echo ""
	@echo '{'
	@echo '  "mcpServers": {'
	@echo '    "uepcap": {'
	@echo '      "command": "$(MCP_PATH)",'
	@echo '      "args": ["--data-dir", "$(DATA_DIR)"]'
	@echo '    }'
	@echo '  }'
	@echo '}'
	@echo ""

# Show MCP config for Cursor
mcp-config-cursor:
	@echo ""
	@echo "========================================"
	@echo "Cursor 配置"
	@echo "========================================"
	@echo "配置文件路径:"
	@echo "  macOS: ~/.cursor/mcp.json"
	@echo "  Windows: %USERPROFILE%/.cursor/mcp.json"
	@echo ""
	@echo "添加以下内容到配置文件:"
	@echo ""
	@echo '{'
	@echo '  "mcpServers": {'
	@echo '    "uepcap": {'
	@echo '      "command": "$(MCP_PATH)",'
	@echo '      "args": ["--data-dir", "$(DATA_DIR)"]'
	@echo '    }'
	@echo '  }'
	@echo '}'
	@echo ""

# Show all MCP configs
mcp-config: mcp-config-claude mcp-config-cursor
	@echo "========================================"
	@echo "通用说明"
	@echo "========================================"
	@echo ""
	@echo "前置依赖: tshark, mergecap (已自动检查)"
	@echo ""
	@echo "提供的工具 (Tools):"
	@echo "  1. uepcap_list_imsis  - 扫描 PCAP 中的 IMSI 列表"
	@echo "  2. uepcap_imsi_brief  - 获取 IMSI 的简要信息（filter + 包数据）"
	@echo ""
	@echo "配置完成后重启 Claude Desktop 或 Cursor 即可使用"
	@echo ""

# Help
help:
	@echo "Available targets:"
	@echo "  make build          - Build frontend and backend (auto-installs deps)"
	@echo "  make build-frontend - Build frontend only (auto-installs npm)"
	@echo "  make build-backend  - Build backend only"
	@echo "  make build-mcp      - Build MCP server binary"
	@echo "  make run            - Build and run production server (auto-installs deps)"
	@echo "  make run-mcp        - Build and run MCP server (stdio transport)"
	@echo "  make dev            - Run backend in development mode (auto-installs deps)"
	@echo "  make test           - Run tests"
	@echo "  make kill           - Kill running uepcap process"
	@echo "  make clean          - Clean build artifacts"
	@echo "  make check-deps     - Check system dependencies"
	@echo "  make install-tshark - Install tshark for current platform"
	@echo "  make install-npm    - Install Node.js and npm for current platform"
	@echo "  make install-mcp    - Build MCP server and show installation info"
	@echo "  make mcp-config     - Show MCP configuration for all clients"
	@echo "  make mcp-config-claude - Show MCP config for Claude Desktop"
	@echo "  make mcp-config-cursor - Show MCP config for Cursor"
