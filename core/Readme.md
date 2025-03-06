# Dependencies

- clang >= 17 (<17 could build the epass tool but could not compile the BPF programs properly)
- Ninja (optional, for faster compilation speed)
- libbpf (you could use ePass libbpf if running ePass kernel)

# Build

If you are using normal kernel, inside this directory, run:

```
cmake -S . -B build -GNinja -DEPASS_LIBBPF=OFF
make
```

If you are running our custom kernel with custom libbpf, compile with:

```
cmake -S . -B build -GNinja -DEPASS_LIBBPF=ON
make
```

# Install

After building, run:

```
sudo cmake --install build
```

## Bugs

### Coalesce has some bugs

Found root cause: you may not directly remove instructions like r1 = r1.

Note. this should be refactored to the last step in the new pipeline.

## Errors

Reproduce: `ringbuf.c` enable coalesce will cause some error in CG

Raw libbpf library loader doesn't change the "imm" value when calling the `callback_fn`. It doesn't support calling it after changing the resources.

## function_arg?

Not sure why there is no function_arg stuffs in code generation.

## ALLOCARRAY?

Why pre-colored?

# TODO

- [ ] Rewrite Normalization, flatten the IR.
- [ ] Refactor CG to use the simpler pipeline described in "Register Allocation via Coloring of Chordal Graphs"
- [ ] bpf-to-bpf calls
