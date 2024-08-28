#include <linux/bpf.h>
#include <time.h>

#include "bpf_ir.h"

enum val_type vtype_insn(struct ir_insn *insn)
{
	insn = dst(insn);
	if (insn == NULL) {
		// Void
		return UNDEF;
	}
	struct ir_insn_cg_extra *extra = insn_cg(insn);
	if (extra->spilled) {
		return STACK;
	} else {
		return REG;
	}
}

enum val_type vtype(struct ir_value val)
{
	if (val.type == IR_VALUE_INSN) {
		return vtype_insn(val.data.insn_d);
	} else if (val.type == IR_VALUE_CONSTANT) {
		return CONST;
	} else if (val.type == IR_VALUE_STACK_PTR) {
		return REG;
	} else {
		CRITICAL("No such value type for dst");
	}
}

void load_stack_to_r0(struct ir_function *fun, struct ir_insn *insn,
		      struct ir_value *val, enum ir_vr_type vtype)
{
	struct ir_insn *tmp = create_assign_insn_cg(insn, *val, INSERT_FRONT);
	tmp->vr_type = vtype;
	insn_cg(tmp)->dst = fun->cg_info.regs[0];

	val->type = IR_VALUE_INSN;
	val->data.insn_d = fun->cg_info.regs[0];
}

void load_const_to_vr(struct ir_insn *insn, struct ir_value *val)
{
	struct ir_insn *tmp = create_assign_insn_cg(insn, *val, INSERT_FRONT);

	val->type = IR_VALUE_INSN;
	val->data.insn_d = tmp;
}

void add_stack_offset_vr(struct ir_function *fun, size_t num)
{
	struct ir_insn **pos;
	array_for(pos, fun->cg_info.all_var)
	{
		struct ir_insn_cg_extra *extra = insn_cg(*pos);
		if (extra->spilled > 0) {
			extra->spilled += num;
		}
	}
}

void spill_callee(struct ir_function *fun)
{
	// Spill Callee saved registers if used
	__u8 reg_used[MAX_BPF_REG] = { 0 };

	struct ir_insn **pos;
	array_for(pos, fun->cg_info.all_var)
	{
		struct ir_insn_cg_extra *extra = insn_cg(*pos);
		reg_used[extra->alloc_reg] = 1;
	}
	size_t off = 0;
	for (__u8 i = BPF_REG_6; i < BPF_REG_10; ++i) {
		if (reg_used[i]) {
			off++;
		}
	}
	DBGASSERT(off == fun->cg_info.callee_num);
	add_stack_offset_vr(fun, off);
	off = 0;
	for (__u8 i = BPF_REG_6; i < BPF_REG_10; ++i) {
		// All callee saved registers
		if (reg_used[i]) {
			off++;
			// Spill at sp-off
			// struct ir_insn *st = create_assign_insn_bb_cg(
			//     fun->entry, ir_value_insn(fun->cg_info.regs[i]), INSERT_FRONT);
			struct ir_insn *st = create_insn_base_cg(fun->entry);
			insert_at_bb(st, fun->entry, INSERT_FRONT);
			st->op = IR_INSN_STORERAW;
			st->values[0] = ir_value_insn(fun->cg_info.regs[i]);
			st->value_num = 1;
			st->vr_type = IR_VR_TYPE_64;
			struct ir_value val;
			val.type = IR_VALUE_STACK_PTR;
			st->addr_val.value = val;
			st->addr_val.offset = -off * 8;
			struct ir_insn_cg_extra *extra = insn_cg(st);
			extra->dst = NULL;

			struct ir_basic_block **pos2;
			array_for(pos2, fun->end_bbs)
			{
				struct ir_basic_block *bb = *pos2;
				struct ir_insn *ld = create_insn_base_cg(bb);
				insert_at_bb(ld, bb, INSERT_BACK_BEFORE_JMP);
				ld->op = IR_INSN_LOADRAW;
				ld->value_num = 0;
				ld->vr_type = IR_VR_TYPE_64;
				struct ir_value val;
				val.type = IR_VALUE_STACK_PTR;
				ld->addr_val.value = val;
				ld->addr_val.offset = -off * 8;

				extra = insn_cg(ld);
				extra->dst = fun->cg_info.regs[i];
			}
		}
	}
}

enum ir_vr_type alu_to_vr_type(enum ir_alu_type ty)
{
	if (ty == IR_ALU_32) {
		return IR_VR_TYPE_32;
	} else if (ty == IR_ALU_64) {
		return IR_VR_TYPE_64;
	} else {
		CRITICAL("Error");
	}
}

int check_need_spill(struct ir_function *fun)
{
	// Check if all instruction values are OK for translating
	int res = 0;
	struct ir_basic_block **pos;
	array_for(pos, fun->reachable_bbs)
	{
		struct ir_basic_block *bb = *pos;
		struct ir_insn *insn;
		list_for_each_entry(insn, &bb->ir_insn_head, list_ptr) {
			struct ir_value *v0 = &insn->values[0];
			struct ir_value *v1 = &insn->values[1];
			enum val_type t0 = insn->value_num >= 1 ? vtype(*v0) :
								  UNDEF;
			enum val_type t1 = insn->value_num >= 2 ? vtype(*v1) :
								  UNDEF;
			enum val_type tdst = vtype_insn(insn);
			struct ir_insn_cg_extra *extra = insn_cg(insn);
			struct ir_insn *dst_insn = dst(insn);
			if (insn->op == IR_INSN_ALLOC) {
				// dst = alloc <size>
				// Nothing to do
			} else if (insn->op == IR_INSN_STORE) {
				// store v0(dst) v1
				// Eequivalent to `v0 = v1`
				insn->op = IR_INSN_ASSIGN;
				DBGASSERT(
					v0->type ==
					IR_VALUE_INSN); // Should be guaranteed by prog_check
				DBGASSERT(v0->data.insn_d->op == IR_INSN_ALLOC);
				insn->vr_type = v0->data.insn_d->vr_type;
				extra->dst = v0->data.insn_d;
				insn->value_num = 1;
				*v0 = *v1;
				res = 1;
			} else if (insn->op == IR_INSN_LOAD) {
				// stack = load stack
				// stack = load reg
				// reg = load reg
				// reg = load stack
				insn->op = IR_INSN_ASSIGN;
				DBGASSERT(
					v0->type ==
					IR_VALUE_INSN); // Should be guaranteed by prog_check
				DBGASSERT(v0->data.insn_d->op == IR_INSN_ALLOC);
				insn->vr_type = v0->data.insn_d->vr_type;
				res = 1;
			} else if (insn->op == IR_INSN_LOADRAW) {
				// Load from memory
				// reg = loadraw reg ==> OK
				// reg = loadraw const ==> OK

				// stack = loadraw addr
				// ==>
				// R0 = loadraw addr
				// stack = R0

				// stack = loadraw stack
				// ==>
				// R0 = stack
				// R0 = loadraw R0
				// stack = R0
				if (tdst == STACK) {
					extra->dst = fun->cg_info.regs[0];
					struct ir_insn *tmp =
						create_assign_insn_cg(
							insn,
							ir_value_insn(
								fun->cg_info
									.regs[0]),
							INSERT_BACK);
					insn_cg(tmp)->dst = dst_insn;
					tmp->vr_type = insn->vr_type;
					res = 1;
				}
				if (vtype(insn->addr_val.value) == STACK) {
					// Question: are all memory address 64 bits?
					load_stack_to_r0(fun, insn,
							 &insn->addr_val.value,
							 IR_VR_TYPE_64);
					res = 1;
				}
			} else if (insn->op == IR_INSN_STORERAW) {
				// Store some value to memory
				// store ptr reg ==> OK
				// store ptr stack

				// store stackptr stack
				// ==> TODO!
				if (t0 == STACK &&
				    vtype(insn->addr_val.value) == STACK) {
					CRITICAL("TODO!");
				}
				if (t0 == CONST &&
				    insn->vr_type == IR_VR_TYPE_64) {
					CRITICAL("Not supported");
				}
				// Question: are all memory address 64 bits?
				if (t0 == STACK) {
					load_stack_to_r0(fun, insn, v0,
							 IR_VR_TYPE_64);
					res = 1;
				}
				if (vtype(insn->addr_val.value) == CONST) {
					CRITICAL("Not Supported");
				}
				if (vtype(insn->addr_val.value) == STACK) {
					load_stack_to_r0(fun, insn,
							 &insn->addr_val.value,
							 IR_VR_TYPE_64);
					res = 1;
				}
			} else if (is_alu(insn)) {
				// Binary ALU
				// reg = add reg reg
				// reg = add reg const
				// There should be NO stack
				if (tdst == STACK) {
					// stack = add ? ?
					// ==>
					// R0 = add ? ?
					// stack = R0
					extra->dst = fun->cg_info.regs[0];
					struct ir_insn *tmp =
						create_assign_insn_cg(
							insn,
							ir_value_insn(
								fun->cg_info
									.regs[0]),
							INSERT_BACK);
					tmp->vr_type =
						alu_to_vr_type(insn->alu);
					insn_cg(tmp)->dst = dst_insn;
					res = 1;
				} else {
					if ((t0 != REG && t1 == REG) ||
					    (t0 == CONST && t1 == STACK)) {
						// reg = add !reg reg
						// ==>
						// reg = add reg !reg
						struct ir_value tmp = *v0;
						*v0 = *v1;
						*v1 = tmp;
						enum val_type ttmp = t0;
						t0 = t1;
						t1 = ttmp;
						// No need to spill here
					}
					if (t0 == REG) {
						// reg = add reg reg ==> OK
						// reg = add reg const ==> OK

						// reg1 = add reg2 stack
						// ==>
						// If reg1 != reg2,
						//   reg1 = stack
						//   reg1 = add reg2 reg1
						// Else
						//   Choose reg3 != reg1,
						//   reg3 = stack
						//   reg1 = add reg1 reg3
						if (t1 == STACK) {
							__u8 reg1 =
								insn_cg(dst_insn)
									->alloc_reg;
							__u8 reg2 =
								insn_cg(v0->data.insn_d)
									->alloc_reg;
							struct ir_insn *new_insn =
								create_assign_insn_cg(
									insn,
									*v1,
									INSERT_FRONT);
							new_insn->vr_type =
								alu_to_vr_type(
									insn->alu);
							v1->type =
								IR_VALUE_INSN;
							if (reg1 == reg2) {
								__u8 reg =
									reg1 == 0 ?
										1 :
										0;
								insn_cg(new_insn)
									->dst =
									fun->cg_info
										.regs[reg];
								v1->data.insn_d =
									fun->cg_info
										.regs[reg];
							} else {
								insn_cg(new_insn)
									->dst =
									fun->cg_info
										.regs[reg1];
								v1->data.insn_d =
									fun->cg_info
										.regs[reg1];
							}
							res = 1;
						}
					} else {
						// reg = add const const ==> OK
						// reg = add c1 c2
						// ==>
						// reg = c1
						// reg = add reg c2
						// OK

						// reg = add stack stack
						if (t0 == STACK &&
						    t1 == STACK) {
							// reg1 = add stack1 stack2
							// ==>
							// Found reg2 != reg1
							// reg1 = stack1
							// reg1 = add reg1 stack2
							__u8 reg1 =
								insn_cg(dst_insn)
									->alloc_reg;
							struct ir_insn *new_insn =
								create_assign_insn_cg(
									insn,
									*v0,
									INSERT_FRONT);
							new_insn->vr_type =
								alu_to_vr_type(
									insn->alu);
							insn_cg(new_insn)->dst =
								fun->cg_info.regs
									[reg1];
							v0->type =
								IR_VALUE_INSN;
							v0->data.insn_d =
								fun->cg_info.regs
									[reg1];
							res = 1;
						}
						// reg = add stack const ==> OK
						// ==>
						// reg = stack
						// reg = add reg const
					}
				}
			} else if (insn->op == IR_INSN_ASSIGN) {
				// stack = reg (sized)
				// stack = const (sized)
				// reg = const (alu)
				// reg = stack (sized)
				// reg = reg
				if (tdst == STACK && t0 == STACK) {
					// Both stack positions are managed by us
					load_stack_to_r0(fun, insn, v0,
							 IR_VR_TYPE_64);
					res = 1;
				}
				if (tdst == STACK && t0 == CONST) {
					if (insn->vr_type == IR_VR_TYPE_64) {
						// First load to R0
						struct ir_insn *new_insn =
							create_assign_insn_cg(
								insn, *v0,
								INSERT_FRONT);
						new_insn->vr_type =
							insn->vr_type;
						insn_cg(new_insn)->dst =
							fun->cg_info.regs[0];
						v0->type = IR_VALUE_INSN;
						v0->data.insn_d =
							fun->cg_info.regs[0];
						res = 1;
					}
				}
			} else if (insn->op == IR_INSN_RET) {
				// ret const/reg
				// Done in explicit_reg pass
				DBGASSERT(insn->value_num == 0);
			} else if (insn->op == IR_INSN_CALL) {
				// call()
				// Should have no arguments
				DBGASSERT(insn->value_num == 0);
			} else if (insn->op == IR_INSN_JA) {
				// OK
			} else if (is_cond_jmp(insn)) {
				// jmp reg const/reg
				__u8 switched = 0;
				if ((t0 != REG && t1 == REG) ||
				    (t0 == CONST && t1 == STACK)) {
					switched = 1;
					struct ir_value tmp = *v0;
					*v0 = *v1;
					*v1 = tmp;
					enum val_type ttmp = t0;
					t0 = t1;
					t1 = ttmp;
					// No need to spill here
				}

				if (t0 == REG) {
					// jmp reg reg ==> OK
					// jmp reg const ==> OK
					// jmp reg stack
					// ==>
					// reg2 = stack
					// jmp reg reg2
					if (t1 == STACK) {
						__u8 reg1 =
							insn_cg(v0->data.insn_d)
								->alloc_reg;
						__u8 reg2 = reg1 == 0 ? 1 : 0;
						struct ir_insn *new_insn =
							create_assign_insn_cg(
								insn, *v1,
								INSERT_FRONT);
						new_insn->vr_type =
							alu_to_vr_type(
								insn->alu);
						insn_cg(new_insn)->dst =
							fun->cg_info.regs[reg2];
						v1->type = IR_VALUE_INSN;
						v1->data.insn_d =
							fun->cg_info.regs[reg2];
						res = 1;
					}
				} else {
					// jmp const1 const2
					// ==>
					// %tmp = const1
					// jmp %tmp const2
					if (t0 == CONST && t1 == CONST) {
						struct ir_insn *new_insn =
							create_assign_insn_cg(
								insn, *v0,
								INSERT_FRONT);
						new_insn->vr_type =
							alu_to_vr_type(
								insn->alu);
						v0->type = IR_VALUE_INSN;
						v0->data.insn_d = new_insn;
						res = 1;
					}
					// jmp stack const
					if (t0 == STACK && t1 == CONST) {
						load_stack_to_r0(
							fun, insn, v0,
							alu_to_vr_type(
								insn->alu));
						res = 1;
					}
					// jmp stack1 stack2
					// ==>
					// R0 = stack1
					// R1 = stack2
					// jmp R0 R1
					if (t0 == STACK && t1 == STACK) {
						load_stack_to_r0(
							fun, insn, v0,
							alu_to_vr_type(
								insn->alu));
						res = 1;
					}
				}
				if (switched) {
					// Switch back
					struct ir_value tmp = *v0;
					*v0 = *v1;
					*v1 = tmp;
				}
			} else {
				CRITICAL("No such instruction");
			}
		}
	}
	return res;
}
