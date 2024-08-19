# bpf IR Specification (v0.1)

## `bpf_insn` Structure

```c
struct ir_insn {
    struct ir_value values[MAX_FUNC_ARG];
    __u8            value_num;

    // Used in ALLOC instructions
    enum ir_vr_type vr_type;

    // Used in RAW instructions
    struct ir_address_value addr_val;

    // Used in JMP instructions
    struct ir_basic_block *bb1;
    struct ir_basic_block *bb2;

    // Array of phi_value
    struct array phi;

    __s32             fid;
    __u32             f_arg_num;
    enum ir_insn_type op;

    // Linked list
    struct list_head list_ptr;

    // Parent BB
    struct ir_basic_block *parent_bb;

    // Array of struct ir_insn *
    // Users
    struct array users;

    // Might be useful?
    // Too difficult, need BTF
    // enum ir_vr_type type;

    // Used when generating the real code
    size_t _insn_id;
    void  *user_data;
    __u8   _visited;
};
```

There are currently 20 instructions supported.

## IR Instructions

General syntax notation for documenting the instructions:

`INSN <FIELD_1> <FIELD_2>...`

`FIELD_1` is a field name in the `bpf_insn` struct.

For example, the following notation is valid syntax notation:

`alloc <vr_type>`

`abort`

`ja <bb1>`

### `alloc`

Syntax: `alloc <vr_type>`.

Allocate a space on stack or on a register (decided by the code gen).

Example:

```
%1 = alloc IR_VR_TYPE_U32
store %1 200
```

### `store`

Syntax: `store <values[0]> <values[1]>`

Requirement: `values[0]` is an `alloc` instruction.

Store a value `values[1]` in an address `values[0]`.

### `load`

Syntax: `load <vr_type> <values[0]>`

Requirement: `values[0]` is an `alloc` instruction.

Load a value `values[0]` with size `vr_type`.

### `storeraw`

Syntax: `storeraw <vr_type> <addr_val> <values[0]>`

Store a value `values[0]` in manually set `addr_val` with size `vr_type`.

### `loadraw`

Syntax: `loadraw <vr_type> <addr_val>`

Load a value `addr_val` with size `vr_type`.

### ALU Binary Instructions

This includes `add`, `sub`, etc.

Syntax: `INSN <values[0]> <values[1]`

Do ALU binary computation.

Example:

```
%3 = add %1 %2
```

### `call`

Syntax: `call <fid> <values[0]> <values[1]>...`

Call a eBPF helper function with arguments `values[0]`...

### `ret`

Syntax: `ret <values[0]>`

Exit the program with exit code `values[0]`.

### `ja`

Syntax: `ja <bb1>`

Jump to basic block `bb1`.

### Conditional Jump Instructions

Syntax: `INSN <values[0]> <values[1]> <bb1> <bb2>`

Do condition jump based on testing `values[0]` and `values[1]`.

`bb1` is the basic block next to this basic block if not jumping, `bb2` is the basic block to jump.

Requirement: `bb1` must be next to this basic block.

### `phi`

Syntax: `phi <phi[0]> <phi[1]>...`

Phi instruction. `phi` is an array of `phi_value`. Each `phi_value` is a `(ir_value, ir_basic_block*)` pair.

## BasicBlock

The basic block structure is `struct ir_basic_block*`.

The instructions in the basic block is stored in `ir_insn_head`. It is a doubly linked list.

The predecessors and successors are stored in `preds` and `succs`. They are arrays of `struct ir_basic_block *`.

Users could add custom data in the `user_data` field. Make sure to free the user data after using it.

## How to build IR

### Create a new instruction

Use functions in `ir_insn`.

It's possible to create an instruction after/before one existing instruction or at the back/front of a basic block.

For example, to create a `alloc` instruction, there are two functions:

```c

struct ir_insn *create_alloc_insn(struct ir_insn *insn, enum ir_vr_type type,
                                  enum insert_position pos);

struct ir_insn *create_alloc_insn_bb(struct ir_basic_block *bb, enum ir_vr_type type,
                                     enum insert_position pos);
```

`insn` is the instruction that you want to insert after/before. `type` is the specific data needed for this instruction. `pos` is the relative position to insert. There are two options: 

```c
enum insert_position {
    INSERT_BACK,
    INSERT_FRONT,
};
```

# BPF ISA

BPF has 10 general purpose registers and a read-only frame pointer register, all of which are 64-bits wide.

The BPF calling convention is defined as:

- R0: return value from function calls, and exit value for BPF programs
- R1 - R5: arguments for function calls
- R6 - R9: callee saved registers that function calls will preserve
- R10: read-only frame pointer to access stack

R0 - R5 are scratch registers and BPF programs needs to spill/fill them if necessary across calls.

The BPF program needs to store the return value into register R0 before doing an EXIT.

