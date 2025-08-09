# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Project Overview

Mercury is an open-source network metadata capture and analysis package for network security monitoring, fingerprinting, and protocol analysis. It consists of:
- **mercury**: High-performance Linux packet capture application using AF_PACKET
- **libmerc**: Core packet processing library (C++17)
- **pmercury**: Python interface via Cython bindings
- **Utilities**: cert_analyze, tls_scanner, batch_gcd for specialized analysis

## Essential Commands

### Build Commands
```bash
# Standard build
./configure && make

# Debug build
make debug-mercury

# Build libraries only
make libs

# Install with systemd service
sudo make install MERCURY_CFG=mercury.cfg

# Non-root installation
sudo make install-nonroot

# Build Cython wheel
cd src/cython && make wheel
```

### Testing Commands
```bash
# Run all tests
make test

# Run unit tests
make unit_tests
cd unit_tests && make

# Generate coverage report
make coverage_report

# Run specific test
cd unit_tests && ./mercury_test "[test_name]"
```

### Development Commands
```bash
# Format code
make format

# Generate documentation
make doc        # Doxygen
make sphinx     # Sphinx docs

# Version management
make increment-patchlevel    # Bump patch version
make increment-minor-version # Bump minor version
```

## Architecture Overview

### Core Components

**libmerc Library** (`src/libmerc/`)
- Main entry point: `libmerc.cc`, `pkt_proc.cc` - packet processing engine
- Protocol parsers in individual files: `tls.cc`, `http.cc`, `dns.cc`, `ssh.cc`, etc.
- Analysis engine: `analysis.cc` - process identification and malware detection
- Memory-safe parsing: `datum.h` - zero-copy packet parsing without heap allocation

**Protocol Fingerprinting**
- TLS fingerprint generation using JA3/JA3S algorithms
- HTTP header fingerprinting
- DNS query pattern analysis
- All fingerprinting code outputs JSON for easy integration

**Performance Critical Paths**
- Packet processing uses lockless ring buffers and memory pools
- JSON output bypasses std::ostream for speed (`json_object.h`)
- Protocol parsing uses fixed-size stack buffers to avoid heap allocation

### Python Integration

The Python interface (`python/pmercury/`) uses Cython bindings (`src/cython/`) to expose:
- `mercury_python` module for packet analysis
- `perform_analysis()` and `perform_analysis_with_weights()` functions
- Direct access to fingerprinting and analysis capabilities

### Key Design Patterns

1. **Safe Parsing**: All protocol parsers use the `datum` class for bounds-checked parsing
2. **JSON Output**: Custom JSON generator optimized for network metadata
3. **Resource Files**: Encrypted archives containing protocol databases and ML models
4. **Platform Abstraction**: Conditional compilation for Linux (AF_PACKET) vs macOS (PCAP only)

## Important Notes

- Primary development platform is Linux; macOS support is limited to PCAP file processing
- C++17 required for compilation
- Performance testing should use AF_PACKET on Linux for accurate results
- When modifying protocol parsers, ensure datum bounds checking is maintained
- New features should include unit tests in `unit_tests/`
- JSON output must follow guidelines in `doc/guidelines.md`