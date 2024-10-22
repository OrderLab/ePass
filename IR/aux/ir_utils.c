#include <linux/bpf_ir.h>

// Insert some instructions to print a message
void bpf_ir_printk_insns(struct bpf_ir_env *env, struct ir_insn *insn,
			 enum insert_position pos, const char *msg)
{
	struct ir_insn *alloc_array =
		bpf_ir_create_allocarray_insn(env, insn, IR_VR_TYPE_64, 1, pos);

	struct ir_insn *straw1 = bpf_ir_create_storeraw_insn(
		env, alloc_array, IR_VR_TYPE_8,
		bpf_ir_addr_val(bpf_ir_value_insn(alloc_array), 0x4),
		bpf_ir_value_const32(0), INSERT_BACK);

	struct ir_insn *straw2 = bpf_ir_create_storeraw_insn(
		env, straw1, IR_VR_TYPE_32,
		bpf_ir_addr_val(bpf_ir_value_insn(alloc_array), 0),
		bpf_ir_value_const32(0x74697865), INSERT_BACK);

	struct ir_insn *elemptr = bpf_ir_create_getelemptr_insn(
		env, straw2, alloc_array, bpf_ir_value_const32(0), INSERT_BACK);

	struct ir_insn *call_insn =
		bpf_ir_create_call_insn(env, elemptr, 6,
					INSERT_BACK); // A printk call

	bpf_ir_add_call_arg(env, call_insn, bpf_ir_value_insn(elemptr));

	bpf_ir_add_call_arg(env, call_insn, bpf_ir_value_const32(5));
}
