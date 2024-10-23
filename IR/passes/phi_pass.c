#include <linux/bpf_ir.h>

static void try_remove_trivial_phi(struct bpf_ir_env *env, struct ir_insn *phi)
{
	if (phi->op != IR_INSN_PHI) {
		return;
	}
	// print_raw_ir_insn(phi);
	struct ir_value same;
	u8 same_has_value = 0;
	struct phi_value *pv_pos;
	array_for(pv_pos, phi->phi)
	{
		struct phi_value pv = *pv_pos;
		if (pv.value.type == IR_VALUE_INSN &&
		    ((same_has_value && same.type == IR_VALUE_INSN &&
		      pv.value.data.insn_d == same.data.insn_d) ||
		     pv.value.data.insn_d == phi)) {
			continue;
		}
		if (same_has_value) {
			return;
		}
		same = pv.value;
		same_has_value = 1;
	}
	// PRINT_LOG("Phi to remove: ");
	// print_raw_ir_insn(phi);
	if (!same_has_value) {
		same.type = IR_VALUE_UNDEF;
	}
	bpf_ir_replace_all_usage_except(env, phi, same, phi);

	bpf_ir_erase_insn(env, phi);
	CHECK_ERR();
}

void remove_trivial_phi(struct bpf_ir_env *env, struct ir_function *fun,
			void *param)
{
	struct ir_basic_block **bpos;
	array_for(bpos, fun->reachable_bbs)
	{
		struct ir_basic_block *bb = *bpos;
		struct ir_insn *pos, *tmp;
		list_for_each_entry_safe(pos, tmp, &bb->ir_insn_head,
					 list_ptr) {
			try_remove_trivial_phi(env, pos);
			CHECK_ERR();
		}
	}
}
