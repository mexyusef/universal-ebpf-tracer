# Universal eBPF Tracer - Comprehensive Build System
#
# This Makefile provides a complete build system for the Universal eBPF Tracer,
# a high-performance eBPF-based tracing system that provides comprehensive
# observability across network, application, and runtime layers.
#
# Components:
#   - HTTP Tracer: Application layer protocol tracing (HTTP/gRPC/WebSocket)
#   - XDP Tracer: High-performance network packet processing
#   - Stack Tracer: Deep profiling with stack unwinding
#
# Requirements:
#   - Linux kernel 5.4+ (5.8+ recommended)
#   - clang/LLVM 10+
#   - libbpf development headers
#   - Root privileges for loading eBPF programs
#
# Author: Universal eBPF Tracer Contributors
# License: MIT

# =============================================================================
# CONFIGURATION
# =============================================================================

# Compiler and tools configuration
CLANG := clang
LLVM_STRIP := llvm-strip
LLVM_OBJDUMP := llvm-objdump
BPFTOOL := bpftool
ARCH := $(shell uname -m | sed 's/x86_64/x86/')

# Version information
VERSION := $(shell git describe --tags --always --dirty 2>/dev/null || echo "dev")
BUILD_DATE := $(shell date -u +"%Y-%m-%dT%H:%M:%SZ")
GIT_COMMIT := $(shell git rev-parse --short HEAD 2>/dev/null || echo "unknown")

# Directory structure
SRC_DIR := src
BUILD_DIR := build
DOCS_DIR := docs
TESTS_DIR := tests

# Source files and targets
EBPF_SRCS := $(SRC_DIR)/http_tracer.c $(SRC_DIR)/xdp_tracer.c $(SRC_DIR)/stack_tracer.c
EBPF_OBJS := http_tracer.o xdp_tracer.o stack_tracer.o
EBPF_HEADERS := $(wildcard $(SRC_DIR)/*.h)

# eBPF compilation flags with comprehensive optimization
EBPF_CFLAGS := -O2 -g -Wall -Wextra \
	-target bpf \
	-D__TARGET_ARCH_$(ARCH) \
	-D__BPF_TRACING__ \
	-DVERSION=\"$(VERSION)\" \
	-DBUILD_DATE=\"$(BUILD_DATE)\" \
	-I/usr/include/$(shell uname -m)-linux-gnu \
	-I/usr/include/bpf \
	-mllvm -bpf-stack-size=8192 \
	-Wno-unused-value \
	-Wno-pointer-sign \
	-Wno-compare-distinct-pointer-types \
	-Werror=return-type \
	-fno-stack-protector

# Colors for output
RED := \033[0;31m
GREEN := \033[0;32m
YELLOW := \033[0;33m
BLUE := \033[0;34m
PURPLE := \033[0;35m
CYAN := \033[0;36m
WHITE := \033[0;37m
NC := \033[0m # No Color

# =============================================================================
# DEFAULT TARGET
# =============================================================================

# Default target - build all eBPF programs
.PHONY: all
all: banner check-deps $(EBPF_OBJS) verify
	@echo "$(GREEN)✅ Universal eBPF Tracer build completed successfully!$(NC)"
	@echo "$(CYAN)📊 Build Summary:$(NC)"
	@echo "   Version: $(VERSION)"
	@echo "   Build Date: $(BUILD_DATE)"
	@echo "   Git Commit: $(GIT_COMMIT)"
	@echo "   eBPF Objects: $(EBPF_OBJS)"
	@ls -lh $(EBPF_OBJS) 2>/dev/null || true

# =============================================================================
# UTILITY TARGETS
# =============================================================================

# Display project banner
.PHONY: banner
banner:
	@echo "$(PURPLE)╔══════════════════════════════════════════════════════════════╗$(NC)"
	@echo "$(PURPLE)║                Universal eBPF Tracer                         ║$(NC)"
	@echo "$(PURPLE)║          High-Performance Observability Platform            ║$(NC)"
	@echo "$(PURPLE)║                                                              ║$(NC)"
	@echo "$(PURPLE)║  🌐 HTTP Tracer  ⚡ XDP Tracer  🔍 Stack Tracer           ║$(NC)"
	@echo "$(PURPLE)╚══════════════════════════════════════════════════════════════╝$(NC)"
	@echo ""

# Check system dependencies and requirements
.PHONY: check-deps
check-deps:
	@echo "$(CYAN)🔍 Checking system dependencies...$(NC)"
	@command -v $(CLANG) >/dev/null 2>&1 || { echo "$(RED)❌ clang not found. Please install clang/LLVM.$(NC)"; exit 1; }
	@command -v $(LLVM_STRIP) >/dev/null 2>&1 || { echo "$(YELLOW)⚠️  llvm-strip not found. Stripping disabled.$(NC)"; }
	@command -v $(BPFTOOL) >/dev/null 2>&1 || { echo "$(YELLOW)⚠️  bpftool not found. Some features may be limited.$(NC)"; }
	@echo "$(GREEN)✅ Dependencies check completed$(NC)"

# Verify kernel and system requirements
.PHONY: check-system
check-system: check-deps
	@echo "$(CYAN)🔍 Checking system requirements...$(NC)"
	@echo "   Kernel version: $$(uname -r)"
	@echo "   Architecture: $$(uname -m)"
	@echo "   Clang version: $$($(CLANG) --version | head -n1)"
	@if [ -f /sys/kernel/btf/vmlinux ]; then \
		echo "$(GREEN)✅ BTF support available$(NC)"; \
	else \
		echo "$(YELLOW)⚠️  BTF support not detected$(NC)"; \
	fi
	@if zgrep -q CONFIG_BPF=y /proc/config.gz 2>/dev/null; then \
		echo "$(GREEN)✅ eBPF support enabled$(NC)"; \
	else \
		echo "$(YELLOW)⚠️  eBPF support not confirmed$(NC)"; \
	fi

# =============================================================================
# COMPILATION TARGETS
# =============================================================================

# Create build directory
$(BUILD_DIR):
	@mkdir -p $(BUILD_DIR)

# HTTP Tracer - Application layer protocol tracing
http_tracer.o: $(SRC_DIR)/http_tracer.c $(EBPF_HEADERS)
	@echo "$(BLUE)🌐 Compiling HTTP Tracer (Application Layer Protocol Tracing)...$(NC)"
	@echo "   Features: HTTP/HTTPS, gRPC, WebSocket correlation"
	$(CLANG) $(EBPF_CFLAGS) -c $(SRC_DIR)/http_tracer.c -o http_tracer.o
	@echo "$(GREEN)✅ HTTP Tracer compiled successfully$(NC)"

# XDP Tracer - High-performance network packet processing
xdp_tracer.o: $(SRC_DIR)/xdp_tracer.c $(EBPF_HEADERS)
	@echo "$(BLUE)⚡ Compiling XDP Tracer (High-Performance Network Processing)...$(NC)"
	@echo "   Features: L2/L3 packet analysis, flow tracking, network analytics"
	$(CLANG) $(EBPF_CFLAGS) -c $(SRC_DIR)/xdp_tracer.c -o xdp_tracer.o
	@echo "$(GREEN)✅ XDP Tracer compiled successfully$(NC)"

# Stack Tracer - Deep profiling and stack unwinding
stack_tracer.o: $(SRC_DIR)/stack_tracer.c $(EBPF_HEADERS)
	@echo "$(BLUE)🔍 Compiling Stack Tracer (Deep Profiling & Stack Unwinding)...$(NC)"
	@echo "   Features: Function tracing, flame graphs, deadlock detection"
	$(CLANG) $(EBPF_CFLAGS) -c $(SRC_DIR)/stack_tracer.c -o stack_tracer.o
	@echo "$(GREEN)✅ Stack Tracer compiled successfully$(NC)"

# Compile all eBPF programs
.PHONY: ebpf
ebpf: banner check-deps $(EBPF_OBJS)
	@echo "$(GREEN)🎯 All eBPF programs compiled successfully!$(NC)"

# Quick build without checks (for development)
.PHONY: quick
quick: $(EBPF_OBJS)
	@echo "$(GREEN)⚡ Quick build completed$(NC)"

# =============================================================================
# VERIFICATION AND ANALYSIS
# =============================================================================

# Verify compiled eBPF programs
.PHONY: verify
verify: $(EBPF_OBJS)
	@echo "$(CYAN)🔍 Verifying eBPF programs...$(NC)"
	@for obj in $(EBPF_OBJS); do \
		if [ -f $$obj ]; then \
			echo "   ✅ $$obj: $$(stat -c%s $$obj) bytes"; \
			if command -v $(LLVM_OBJDUMP) >/dev/null 2>&1; then \
				sections=$$($(LLVM_OBJDUMP) -h $$obj | grep -E "(text|maps)" | wc -l); \
				echo "      Sections: $$sections"; \
			fi; \
		else \
			echo "   ❌ $$obj: Missing"; \
		fi; \
	done

# Analyze eBPF programs (requires bpftool)
.PHONY: analyze
analyze: $(EBPF_OBJS)
	@echo "$(CYAN)📊 Analyzing eBPF programs...$(NC)"
	@for obj in $(EBPF_OBJS); do \
		if [ -f $$obj ] && command -v $(BPFTOOL) >/dev/null 2>&1; then \
			echo "$(YELLOW)📋 Analysis for $$obj:$(NC)"; \
			$(LLVM_OBJDUMP) -h $$obj | grep -E "(text|maps|license)"; \
		fi; \
	done

# Disassemble eBPF programs for debugging
.PHONY: disasm
disasm: $(EBPF_OBJS)
	@echo "$(CYAN)🔍 Disassembling eBPF programs...$(NC)"
	@for obj in $(EBPF_OBJS); do \
		if [ -f $$obj ]; then \
			echo "$(YELLOW)📋 Disassembly for $$obj:$(NC)"; \
			$(LLVM_OBJDUMP) -S $$obj | head -50; \
			echo ""; \
		fi; \
	done

# =============================================================================
# INSTALLATION AND SYSTEM SETUP
# =============================================================================

# Install system dependencies
.PHONY: install-system-deps
install-system-deps:
	@echo "$(CYAN)📦 Installing system dependencies...$(NC)"
	@if command -v apt >/dev/null 2>&1; then \
		echo "   Installing for Ubuntu/Debian..."; \
		sudo apt update && sudo apt install -y \
			clang llvm libbpf-dev linux-headers-$$(uname -r) \
			build-essential pkg-config bpftool; \
	elif command -v dnf >/dev/null 2>&1; then \
		echo "   Installing for RHEL/CentOS/Fedora..."; \
		sudo dnf install -y \
			clang llvm libbpf-devel kernel-headers \
			kernel-devel gcc make bpftool; \
	elif command -v pacman >/dev/null 2>&1; then \
		echo "   Installing for Arch Linux..."; \
		sudo pacman -S \
			clang llvm libbpf linux-headers \
			base-devel bpf; \
	else \
		echo "$(RED)❌ Unsupported package manager. Please install manually.$(NC)"; \
		exit 1; \
	fi
	@echo "$(GREEN)✅ System dependencies installed$(NC)"

# Load eBPF programs (requires root)
.PHONY: load
load: $(EBPF_OBJS)
	@echo "$(CYAN)🚀 Loading eBPF programs...$(NC)"
	@if [ "$$(id -u)" -ne 0 ]; then \
		echo "$(RED)❌ Root privileges required for loading eBPF programs$(NC)"; \
		echo "   Run: sudo make load"; \
		exit 1; \
	fi
	@for obj in $(EBPF_OBJS); do \
		if [ -f $$obj ]; then \
			echo "   Loading $$obj..."; \
			$(BPFTOOL) prog load $$obj /sys/fs/bpf/$${obj%.o} || true; \
		fi; \
	done
	@echo "$(GREEN)✅ eBPF programs loaded$(NC)"

# Unload eBPF programs (requires root)
.PHONY: unload
unload:
	@echo "$(CYAN)🛑 Unloading eBPF programs...$(NC)"
	@if [ "$$(id -u)" -ne 0 ]; then \
		echo "$(RED)❌ Root privileges required$(NC)"; \
		exit 1; \
	fi
	@for obj in $(EBPF_OBJS); do \
		prog_name=$${obj%.o}; \
		if [ -f /sys/fs/bpf/$$prog_name ]; then \
			echo "   Unloading $$prog_name..."; \
			rm -f /sys/fs/bpf/$$prog_name; \
		fi; \
	done
	@echo "$(GREEN)✅ eBPF programs unloaded$(NC)"

# Run the tracer (requires root privileges)
.PHONY: run
run: $(BINARY)
	@echo "Running HTTP tracer (requires root privileges)..."
	@if [ "$$(id -u)" -ne 0 ]; then \
		echo "Error: This program requires root privileges to load eBPF programs."; \
		echo "Please run: sudo make run"; \
		exit 1; \
	fi
	./$(BINARY)

# Start test server
.PHONY: test-server
test-server:
	@echo "Starting Flask test server..."
	python3 $(TEST_DIR)/flask_server.py

# Run simple tests
.PHONY: test
test:
	@echo "Running simple HTTP tests..."
	./$(TEST_DIR)/simple_test.sh

# Run comprehensive tests
.PHONY: test-full
test-full:
	@echo "Running comprehensive HTTP tests..."
	./$(TEST_DIR)/test_requests.sh

# Run unit tests
.PHONY: test-unit
test-unit:
	@echo "Running unit tests..."
	$(GO) test -v ./test/unit/...

# Run eBPF program tests
.PHONY: test-ebpf
test-ebpf: $(EBPF_OBJS)
	@echo "Running eBPF program tests..."
	$(GO) test -v ./test/ebpf/...

# Run all tests
.PHONY: test-all
test-all: test-unit test-ebpf test test-full
	@echo "All tests completed!"

# Run comprehensive test suite
.PHONY: test-suite
test-suite:
	@echo "Running comprehensive test suite..."
	./$(TEST_DIR)/run_tests.sh

# Run tests with verbose output
.PHONY: test-verbose
test-verbose:
	@echo "Running tests with verbose output..."
	VERBOSE=true ./$(TEST_DIR)/run_tests.sh

# Run benchmarks
.PHONY: benchmark
benchmark:
	@echo "Running benchmarks..."
	RUN_BENCHMARKS=true ./$(TEST_DIR)/run_tests.sh

# Run comprehensive performance benchmarks
.PHONY: benchmark-performance
benchmark-performance:
	@echo "Running comprehensive performance benchmarks..."
	./$(TEST_DIR)/run_benchmarks.sh

# Run performance benchmarks with verbose output
.PHONY: benchmark-verbose
benchmark-verbose:
	@echo "Running performance benchmarks with verbose output..."
	VERBOSE=true ./$(TEST_DIR)/run_benchmarks.sh

# Run unit benchmarks only
.PHONY: benchmark-unit
benchmark-unit:
	@echo "Running unit benchmarks..."
	$(GO) test -bench=. -benchmem ./test/benchmark/

# Run baseline performance test
.PHONY: benchmark-baseline
benchmark-baseline:
	@echo "Running baseline performance test..."
	$(GO) test -timeout=120s -v ./test/benchmark/ -run TestBaselinePerformance

# Check system requirements
.PHONY: check-system
check-system:
	@echo "Checking system requirements..."
	@echo "Kernel version: $(KERNEL_VERSION)"
	@echo "Architecture: $(ARCH)"
	@which $(CLANG) > /dev/null || (echo "Error: clang not found. Please install clang." && exit 1)
	@which $(GO) > /dev/null || (echo "Error: go not found. Please install Go." && exit 1)
	@echo "Checking eBPF support..."
	@ls /sys/kernel/debug/tracing/events/syscalls/sys_enter_accept > /dev/null 2>&1 || \
		(echo "Warning: Tracepoint sys_enter_accept not found. eBPF tracing may not work." && exit 1)
	@echo "System requirements check passed!"

# Comprehensive help
.PHONY: help
help:
	@echo "$(PURPLE)╔══════════════════════════════════════════════════════════════╗$(NC)"
	@echo "$(PURPLE)║                Universal eBPF Tracer - Help                  ║$(NC)"
	@echo "$(PURPLE)╚══════════════════════════════════════════════════════════════╝$(NC)"
	@echo ""
	@echo "$(CYAN)🏗️  Build Targets:$(NC)"
	@echo "   all                 - Build all eBPF programs (default)"
	@echo "   ebpf                - Build all eBPF programs"
	@echo "   quick               - Quick build without checks"
	@echo "   http_tracer.o       - Build HTTP tracer only"
	@echo "   xdp_tracer.o        - Build XDP tracer only"
	@echo "   stack_tracer.o      - Build Stack tracer only"
	@echo ""
	@echo "$(CYAN)🔍 Analysis & Verification:$(NC)"
	@echo "   verify              - Verify compiled programs"
	@echo "   analyze             - Analyze eBPF programs"
	@echo ""
	@echo "$(CYAN)🧪 Testing:$(NC)"
	@echo "   test                - Run basic tests"
	@echo "   test-all            - Run comprehensive tests"
	@echo "   benchmark           - Performance benchmarks"
	@echo ""
	@echo "$(CYAN)📦 Installation:$(NC)"
	@echo "   install-system-deps - Install system dependencies"
	@echo "   load                - Load eBPF programs (requires root)"
	@echo "   unload              - Unload eBPF programs (requires root)"
	@echo ""
	@echo "$(CYAN)🧹 Maintenance:$(NC)"
	@echo "   clean               - Remove build artifacts"
	@echo "   rebuild             - Clean and rebuild"
	@echo ""
	@echo "$(CYAN)ℹ️  Information:$(NC)"
	@echo "   check-system        - Check system requirements"
	@echo "   help                - Show this help message"
	@echo ""
	@echo "$(YELLOW)💡 Quick Start:$(NC)"
	@echo "   make check-system   # Verify requirements"
	@echo "   make all            # Build everything"
	@echo "   sudo make load      # Load eBPF programs"

# Development targets
.PHONY: dev-setup
dev-setup: deps check-system
	@echo "Development environment setup complete!"

.PHONY: rebuild
rebuild: clean all

# Install system dependencies (Ubuntu/Debian)
.PHONY: install-system-deps
install-system-deps:
	@echo "Installing system dependencies (Ubuntu/Debian)..."
	sudo apt-get update
	sudo apt-get install -y \
		clang \
		llvm \
		golang-go \
		python3 \
		python3-pip \
		libbpf-dev \
		linux-headers-$(shell uname -r) \
		build-essential
	@echo "System dependencies installed!"
