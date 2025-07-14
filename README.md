# ePass

[![Build ePass](https://github.com/OrderLab/ePass/actions/workflows/build.yml/badge.svg)](https://github.com/OrderLab/ePass/actions/workflows/build.yml)

ePass is an in-kernel LLVM-like compiler framework that introduces an SSA-based intermediate representation (IR) for eBPF programs. It provides a lifter that lifts eBPF bytecode to ePass IR, a pass runner that runs user-defined passes, and a code generator that compiles IR to eBPF bytecode. Users could write flexible passes using our LLVM-like APIs to analyze and manipulate the IR.
ePass could work with the verifier to improve its flexibility (i.e. reduce false rejections) and safety (i.e. reduce false acceptance at runtime). It could also be used in userspace for testing.

## Key Features

- **IR-based compilation**: Converts BPF programs to an SSA-based intermediate representation for code rewriting
- **Flexible passes**: ePass core provides various APIs to analyze and manipulate the IR, allowing users to write flexible passes including runtime checks and optimization.
- **Command-line interface**: Easy-to-use CLI tool for testing in userspace

> ePass is under active development and we are improving its usability and safety. We welcome any suggestions and feedback. Feel free to open issues or contact us.

## Design Goals

- Flexible passes, allowing diverse use cases
- Working with existing verifier instead of replacing its
- Keeping kernel safety

## Prerequisites

- **clang >= 17**
- **Ninja** (optional, for faster compilation)
- **libbpf**

## Project Components

- `ePass core`: the core compiler framework
- `ePass kernel`: Linux kernel 6.5 with ePass core built-in, along with the kernel component and kernel passes
- `ePass libbpf`: libbpf with ePass support for userspace ePass testing
- `ePass bpftool`: support for ePass

## Quick Start

The main development happens in `core` directory. To start, `cd` into `core`.

### Build

```bash
make configure # Do it once

make build
```

### Install

```bash
make install
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

### Generate Additional Assets

```bash
# Generate kernel objects
make kernel

# Build ePass object files for libbpf
make buildobj
```


## Contact and citation

Feel free to open an issue for question, bug report or feature request! You could also email xiangyiming2002@gmail.com

## Acknowledgement

ePass is sponsoredby OrderLab from University of Michigan.

