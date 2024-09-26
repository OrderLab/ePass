# Common patterns when writing passes

## Iterate through all the instructions (unsafe, readonly)

```c
struct ir_basic_block **pos;
array_for(pos, fun->reachable_bbs)
{
    struct ir_basic_block *bb = *pos;
    struct ir_insn *insn;
    list_for_each_entry(insn, &bb->ir_insn_head, list_ptr) {
    
    }
}
```