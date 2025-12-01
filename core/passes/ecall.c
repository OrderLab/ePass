// SPDX-License-Identifier: GPL-2.0-only
#include "ir.h"
#include "linux/bpf_ir.h"

bool is_nonptr(struct ir_value v)
{
	// Check if the instruction is a numeric value instead of a pointer (to some map etc.)
	if (v.type == IR_VALUE_INSN) {
		struct ir_insn *insn = v.data.insn_d;
		if (insn->op == IR_INSN_LOADRAW) {
			return true;
		} else if (bpf_ir_is_bin_alu(insn)) {
			return is_nonptr(insn->values[0]) &&
			       is_nonptr(insn->values[1]);
		} else {
			return false;
		}
	} else {
		return true;
	}
}

void translate_heap(struct bpf_ir_env *env, struct ir_function *fun,
		    struct ir_insn *insn)
{
	// Init
	if (insn->value_num != 2) {
		RAISE_ERROR("Init heap argument number error!");
	}
	struct ir_value arg0 = insn->values[0]; // Data map pointer
	if (arg0.type != IR_VALUE_INSN) {
		RAISE_ERROR("Init heap argument 0 must be a data pointer!");
	}
	struct ir_insn *map_insn = arg0.data.insn_d;

	struct ir_value arg1 = insn->values[1];
	if (arg1.type != IR_VALUE_CONSTANT) {
		RAISE_ERROR("Init heap argument 1 must be a constant!");
	}

	// u64 heap_size = arg1.data.constant_d;
	bpf_ir_erase_insn(env, insn);
	// Change all load & store to add a range check
	// load x
	// ->
	// if x < size (unsigned)
	// read from map and return map+x

	// store x
	// ->
	// if x < size (unsigned)
	// store to map at map+x

	// Can use verifier's info about reg's data type
	struct ir_basic_block **pos;
	array_for(pos, fun->reachable_bbs)
	{
		struct ir_basic_block *bb = *pos;
		struct ir_insn *insn;
		list_for_each_entry(insn, &bb->ir_insn_head, list_ptr) {
			if (insn->op == IR_INSN_STORERAW) {
			}
			if (insn->op == IR_INSN_LOADRAW) {
				struct ir_address_value addr_val =
					insn->addr_val;
				if (addr_val.value.type != IR_VALUE_INSN) {
					continue;
				}
				if (!is_nonptr(addr_val.value)) {
					// Pointer type, skip
					continue;
				}
				struct ir_insn *val_insn =
					addr_val.value.data.insn_d;
				int offset = addr_val.offset;
				if (offset != 0) {
					val_insn = bpf_ir_create_bin_insn(
						env, insn,
						bpf_ir_value_insn(val_insn),
						bpf_ir_value_const32(offset),
						IR_INSN_ADD, IR_ALU_64,
						INSERT_FRONT);
				}

				struct ir_insn *alloc_array =
					bpf_ir_create_allocarray_insn(
						env, insn, IR_VR_TYPE_64, 1,
						INSERT_FRONT);

				bpf_ir_create_storeraw_insn(
					env, insn, IR_VR_TYPE_64,
					bpf_ir_addr_val(
						bpf_ir_value_insn(alloc_array),
						0),
					bpf_ir_value_insn(val_insn),
					INSERT_FRONT);

				struct ir_insn *elemptr =
					bpf_ir_create_getelemptr_insn(
						env, insn, alloc_array,
						bpf_ir_value_const32(0),
						INSERT_FRONT);

				// Read data from map
				struct ir_insn *insn2 = bpf_ir_create_call_insn(
					env, insn, 1, INSERT_FRONT);
				bpf_ir_add_call_arg(
					env, insn2,
					bpf_ir_value_insn(map_insn));
				bpf_ir_add_call_arg(env, insn2,
						    bpf_ir_value_insn(elemptr));
				bpf_ir_change_value(env, insn,
						    &insn->addr_val.value,
						    bpf_ir_value_insn(insn2));
				insn->addr_val.offset = 0;
			}
		}
	}
}

/**
 * bpf_ir_handle_ecalls - Handle ecall instructions in the IR
 *
 * This pass translates ecall instructions into appropriate IR instructions
 * according to the semantics defined for ecall operations.
 */

void bpf_ir_handle_ecalls(struct bpf_ir_env *env, struct ir_function *fun,
			  void *param)
{
	struct ir_basic_block **pos;
	array_for(pos, fun->reachable_bbs)
	{
		struct ir_basic_block *bb = *pos;
		struct ir_insn *insn, *tmp;
		list_for_each_entry_safe(insn, tmp, &bb->ir_insn_head,
					 list_ptr) {
			if (insn->op == IR_INSN_ECALL) {
				switch (insn->fid) {
				case 0:
					translate_heap(env, fun, insn);
				default:
					break;
				}
			}
		}
	}
}
