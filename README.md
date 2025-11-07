# crust

CRIU - checkpoint and restore in Rust.

## Building

```bash
# Install system dependencies (Ubuntu/Debian)
make deps

# Build in debug mode
make

# Build optimized release binary
make release

# Install system-wide (requires sudo)
sudo make install

# Uninstall
sudo make uninstall

# Clean build artifacts
make clean

# Or use cargo directly
cargo build --release
```

## Usage

```bash
# Parse and validate a CRIU checkpoint (after make install)
crust --image-dir /path/to/checkpoint

# Or run directly from the build directory
./target/release/crust --image-dir /path/to/checkpoint
```

## Attribution

The protobuf definitions in `proto/` are from [CRIU](https://github.com/checkpoint-restore/criu), licensed under MIT (see SPDX headers in files).

## License

This project is [licensed](LICENSE) under the **GNU Affero General Public License v3.0 (AGPL-3.0)**.
