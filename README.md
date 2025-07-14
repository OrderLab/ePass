# ePass

[![Build ePass](https://github.com/OrderLab/ePass/actions/workflows/build.yml/badge.svg)](https://github.com/OrderLab/ePass/actions/workflows/build.yml)

ePass is an in-kernel LLVM-like compiler framework that introduces an SSA-based intermediate representation (IR) for eBPF programs. It provides a lifter that lifts eBPF bytecode to ePass IR, a pass runner that runs user-defined passes, and a code generator that compiles IR to eBPF bytecode. Users could write flexible passes using our LLVM-like APIs to analyze and manipulate the IR.
ePass could work with the verifier to improve its flexibility (i.e. reduce false rejections) and safety (i.e. reduce false acceptance at runtime). It could also be used in userspace for testing.

## Key Features

- **IR-based compilation**: Converts BPF programs to an SSA-based intermediate representation for code rewriting
- **Flexible passes**: ePass core provides various APIs to analyze and manipulate the IR, allowing users to write flexible passes including static analyzing, runtime checks, and optimization.
- **User-friendly debugging**: ePass supports compiling to both kernel and userspace for easier debugging.

> ePass is under active development and we are improving its usability and safety. We welcome any suggestions and feedback. Feel free to open issues or contact us.

## Design Goals

- Flexible passes for diverse use cases
- Working with existing verifier instead of replacing its
- Keeping kernel safety
- Support both userspace and kernel

## Prerequisites

- **clang >= 17**
- **Ninja** (optional, for faster compilation)
- **libbpf**

## Project Components

- `ePass core`: the core compiler framework, including a userspace CLI
- `ePass kernel`: Linux kernel 6.5 with ePass core built-in, along with the kernel component and kernel passes
- `ePass libbpf`: libbpf with ePass support for userspace ePass testing

There are some testing projects including `bpftool`, `xdp-tools`, `falcolib` in `third-party`. They depend on `ePass libbpf`.

### ePass Overview

![Overview](./docs/overview.png)

### ePass Core

![Core Architecture](./docs/core_design.png)

## Quick Start

There are two ways to use ePass. The first way is to build a linux kernel with ePass builtin, which is used for production. Users could specify ePass options when calling the `BPF` system call. See [Kernel Testing](docs/KERNEL_TESTING.md).

The second way is to build ePass in userspace and testing programs without changing the kernel, which is used mainly for testing. Users could specify ePass options via environment variable and use `ePass libbpf`. Programs will be modified in userspace before sending to the kernel. See [Userspace Testing](docs/USERSPACE_TESTING.md).

We recommend users trying ePass in userspace before switching to the ePass kernel version!

## Testing

See [Testing](./docs/TESTING.md).

## Development and Contribution

See [Development](./docs/CONTRIBUTION_GUIDE.md).

## Contact and citation

Feel free to open an issue for question, bug report or feature request! You could also email <xiangyiming2002@gmail.com>.

## Acknowledgement

ePass is sponsored by [OrderLab](https://orderlab.io/) from University of Michigan.
