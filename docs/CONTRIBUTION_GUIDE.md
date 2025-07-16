# Contribution Guide


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
