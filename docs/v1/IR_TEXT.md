# ePass IR Text Format (`.epir`)

`epass-ir` provides a parseable text format for debugging, pass development, and
round-tripping IR through files. The format is intentionally human-readable and
is **not** a stable external ABI yet.

## Library API

```rust
use epass_ir::{dump_ir, load_ir_file, load_ir_str, DumpOptions};

let text = dump_ir(&func);
let func = load_ir_str(&text)?;
let func = load_ir_file("/tmp/prog.epir")?;
```

Passes can call the dumper directly:

```rust
let text = epass_ir::ir::text::dump_function(func);
std::fs::write("/tmp/after-pass.epir", text)?;
```

The loader rebuilds semantic IR state only. Arena indices, def-use lists,
reachable block lists, and CFG metadata are reconstructed after parsing.

## Loading IR through the pipeline

`load_ir=<path>` is available as a global option:

```bash
epasstool read --gopt load_ir=/tmp/prog.epir dummy.txt
```

When set, ePass skips bytecode lifting, loads the IR file as the initial
`Function`, then still runs the normal pass pipeline and code generator:

```text
load_ir -> postprocess/check -> const_prop -> phi -> custom passes -> codegen
```

There is no global dump option. To dump the IR immediately after lift/load, use
the optional `dump_ir` pass option:

```bash
epasstool read -P --popt 'dump_ir(/tmp/prog.epir)' prog.o
```

The dump pass is optional and orders itself before all other passes. If enabled,
the effective default order is:

```text
dump_ir -> const_prop -> phi -> optimize_ir
```

Without `dump_ir`, the default order is:

```text
const_prop -> phi -> optimize_ir
```

Pass options use the general pass-option format `pass(arg)` / `!pass`; they do
not directly define ordering. Each pass defines its own order.

## Basic syntax

Comments begin with `;`.

```text
; ePass IR v1

bb0: ; preds=[] succs=[bb1,bb2]
  %0 = loadraw.u64 [%arg0+0]
  %1 = add64 %0, 1:i64
  jeq64 %1, 10:i64 -> bb2 else bb1

bb1:
  ret %1

bb2:
  ret 0:i64
```

`preds`/`succs` comments are emitted for readability and ignored by the parser;
CFG edges are reconstructed from terminators.

## Values

Special values:

```text
%sp       ; stack/frame pointer pseudo (R10)
%arg0     ; function argument pseudo (R1)
%arg1
...
%arg4
undef
```

Plain constants:

```text
0:i32
0:i64
-1:i32
42:i64
```

Only plain constants are accepted by the parser in the MVP. Non-plain constants
such as stack-relative offsets and builtin constants may be dumped as diagnostic
`const(...)` forms, but are not intended as stable parse input yet.

## Supported instructions

The parser supports the main pre-codegen IR instructions:

```text
%x = alloc u64
%x = allocarray u8 x 32
%x = getelemptr %idx, %arr

store %slot, %value
%x = load %slot

%x = loadimm.imm64 123
%x = loadimm.map_by_fd 4
%x = loadimm.map_val_fd 17179869188

%x = loadraw.u64 [%base+8]
storeraw.u32 [%base-16], %value

%x = add64 %a, %b
%x = sub32 %a, 1:i32
%x = mul64 %a, %b
%x = div64 %a, %b
%x = mod64 %a, %b
%x = and32 %a, 255:i32
%x = or64 %a, %b
%x = xor64 %a, %b
%x = lsh64 %a, 1:i64
%x = rsh64 %a, 1:i64
%x = arsh64 %a, 1:i64
%x = neg64 %a
%x = end.be32 %a
%x = end.le16 %a

%x = call #6(%fmt, 16:i32)
%x = ecall(%a, %b)

ret %x
throw
ja bb1
jeq64 %a, 0:i64 -> bb2 else bb1
jsgt32 %a, -1:i32 -> bb3 else bb4

%x = phi [%a, bb1], [0:i64, bb2]
%x = assign %a
```

Pseudo instructions (`reg Rn`, `funcarg n`) can be dumped and parsed, but normal
pre-codegen IR should reference `%sp` and `%argN` instead of creating new pseudos.

## Branch target convention

Conditional branches use explicit labels:

```text
jeq64 lhs, rhs -> taken_bb else fallthrough_bb
```

Internally this maps to:

- `bb2 = taken_bb`
- `bb1 = fallthrough_bb`

## Validation after load

The pipeline runs `postprocess` after loading:

1. recompute CFG successors from terminators;
2. recompute reachable block layout;
3. drop edges from unreachable blocks;
4. prune phi inputs from dead predecessors;
5. run `prog_check`.

`prog_check` validates def-use consistency, branch structure, and phi predecessor
consistency.

## Current limitations

- The text format is versioned as `v1` but not yet a stable ABI.
- Parser support is focused on pre-codegen IR. Post-codegen/CG-specific values are
  diagnostic only.
- Parser currently accepts plain constants only as stable input.
- The loader reconstructs fresh arena IDs; do not rely on old `InsnId` values.
