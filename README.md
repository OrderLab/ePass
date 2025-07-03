# ePass

ePass is an in-kernel LLVM-like compiler framework that introduces an SSA-based intermediate representation (IR) for eBPF programs. It provides a lifter that lifts eBPF bytecode to ePass IR, a pass runner that runs user-defined passes, and a code generator that compiles IR to eBPF bytecode. Users could write flexible passes using our LLVM-like APIs to analyze and manipulate the IR.
ePass could work with the verifier to improve its flexibility (i.e. reduce false rejections) and safety (i.e. reduce false acceptance at runtime). It could also be used in userspace for testing.

## Features

- **IR-based compilation**: Converts BPF programs to an SSA-based intermediate representation for code rewriting
- **Flexible passes**: ePass core provides various APIs to analyze and manipulate the IR, allowing users to write flexible passes including runtime checks and optimization.
- **Command-line interface**: Easy-to-use CLI tool for testing in userspace

## Prerequisites

- **clang >= 17**
- **Ninja** (optional, for faster compilation)
- **libbpf**

## Quick Start

### Build

```bash
cmake -S . -B build -GNinja
make
```

### Install

```bash
sudo cmake --install build
```

### Basic Usage

```bash
# Run ePass on the program
epass read prog.o

# Run ePass on the program with gopt and popt
epass read --popt popts --gopt gopts prog.o

# Print the BPF program
epass print prog.o
```

## Development

### Build Commands

```bash
# Format code
make format

# Configure build system (run for the first time)
make configure

# Build with generated constructors (run after you create a new instruction)
make buildall

# Default Build
make build
```

### Testing

```bash
# Run integration tests
cd test && ./run_tests.sh

# Run Python test suite
cd test && python test.py
```

### Generate Additional Assets

```bash
# Generate kernel objects
make kernel

# Build ePass object files for libbpf
make buildobj
```

## Project Structure

```
ePass/
├── core/                 # Main compiler implementation
│   ├── include/          # Header files
│   ├── docs/             # Technical documentation
│   ├── passes/           # Optimization passes
│   ├── aux/              # Auxiliary utilities
│   ├── epasstool/        # CLI tool
│   └── tests/            # Simple BPF tests
├── test/                 # Integration tests and evaluation
├── rejected/             # Collected rejected programs
└── tools/                # Helper scripts and utilities
```

## Contributing

1. Follow the existing code style and patterns
2. Run `make format` before submitting changes
3. Ensure all tests pass
4. Update documentation as needed

## Common Development Patterns

### Iterating Through Instructions

```c
struct ir_basic_block **pos;
array_for(pos, fun->reachable_bbs)
{
    struct ir_basic_block *bb = *pos;
    struct ir_insn *insn;
    list_for_each_entry(insn, &bb->ir_insn_head, list_ptr) {
        // Process instruction
    }
}
```

## TODO

- [ ] bpf-to-bpf calls
- [ ] Full test suite
