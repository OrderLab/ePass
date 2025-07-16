# Userspace Testing

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

For `gopt` and `popt`, see [ePass Options](./EPASS_OPTIONS.md).

### Use ePass with `libbpf`

We may want to load a ePass-modified program to the kernel to see its effect. ePass provides a modified libbpf that allows users to run ePass before loading programs to the kernel. The advantage is that you do not need to change the kernel. However, running ePass in userspace cannot leverage the verifier, so it cannot use verifier information, cannot run verifier dependent passes, and cannot run kernel passes.

First, initializing all submodules.

```bash
git submodule update --init --recursive
```

Now open the `libbpf` source code directory and build:

```bash
cd third-party/ePass-libbpf/src
make -j
```

To install `ePass libbpf`, install:

```bash
sudo make install
```

After installing ePass libbpf, you could run any programs that depends on the `libbpf` shared library with `ePass` commands.

For `bpftool`, you need to build `bpftool` because by default it statically link `libbpf`.

An example of using ePass to load `test.o` eBPF program using `bpftool`:

```bash
sudo LIBBPF_ENABLE_EPASS=1 LIBBPF_EPASS_GOPT="verbose=3" LIBBPF_EPASS_POPT="msan" bpftool prog load test.o /sys/fs/bpf/test
```