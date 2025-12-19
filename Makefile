.PHONY: all build build-frontend build-backend run dev test clean

# Default target
all: build

# Build everything
build: build-frontend build-backend

# Build frontend
build-frontend:
	@echo "Building frontend..."
	cd web && npm install && npm run build

# Build backend
build-backend:
	@echo "Building backend..."
	go build -o uepcap ./cmd/server

# Run production server
run: build
	./uepcap -port 8080

# Run in development mode (requires two terminals)
dev:
	@echo "Starting backend..."
	@echo "Run 'cd web && npm run dev' in another terminal for frontend"
	go run ./cmd/server -port 8080

# Run tests
test:
	go test ./... -v

# Clean build artifacts
clean:
	rm -f uepcap
	rm -rf cmd/server/dist
	rm -rf data/tmp/*
	cd web && rm -rf node_modules dist

# Check dependencies
check-deps:
	@which tshark > /dev/null || (echo "tshark not found. Please install wireshark." && exit 1)
	@which mergecap > /dev/null || (echo "mergecap not found. Please install wireshark." && exit 1)
	@which go > /dev/null || (echo "go not found. Please install Go 1.21+." && exit 1)
	@which node > /dev/null || (echo "node not found. Please install Node.js 18+." && exit 1)
	@echo "All dependencies OK!"

# Help
help:
	@echo "Available targets:"
	@echo "  make build          - Build frontend and backend"
	@echo "  make build-frontend - Build frontend only"
	@echo "  make build-backend  - Build backend only"
	@echo "  make run            - Build and run production server"
	@echo "  make dev            - Run backend in development mode"
	@echo "  make test           - Run tests"
	@echo "  make clean          - Clean build artifacts"
	@echo "  make check-deps     - Check system dependencies"
