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

### `store`

Syntax: `store <vr_type> <values[0]> <values[1]>`

Store a value `values[1]` in an address `values[0]` with size `vr_type`.
