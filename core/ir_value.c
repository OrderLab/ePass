// SPDX-License-Identifier: GPL-2.0-only
#include <linux/bpf_ir.h>
#include <time.h>

bool bpf_ir_value_equal(struct ir_value a, struct ir_value b)
{
	if (a.type != b.type) {
		return false;
	}
	if (a.type == IR_VALUE_CONSTANT) {
		return a.data.constant_d == b.data.constant_d;
	}
	if (a.type == IR_VALUE_INSN) {
		return a.data.insn_d == b.data.insn_d;
	}
	CRITICAL("Error");
}

static struct ir_value value_base(void)
{
	// Create a new value
	return (struct ir_value){ .type = IR_VALUE_UNDEF,
				  .raw_pos = { .valid = false },
				  .const_type = IR_ALU_UNKNOWN,
				  .builtin_const = IR_BUILTIN_NONE };
}

struct ir_value bpf_ir_value_insn(struct ir_insn *insn)
{
	struct ir_value v = value_base();
	v.type = IR_VALUE_INSN;
	v.data.insn_d = insn;
	return v;
}

struct ir_value bpf_ir_value_undef(void)
{
	struct ir_value v = value_base();
	v.type = IR_VALUE_UNDEF;
	return v;
}

struct ir_value bpf_ir_value_const32(s32 val)
{
	struct ir_value v = value_base();
	v.type = IR_VALUE_CONSTANT;
	v.data.constant_d = val;
	v.const_type = IR_ALU_32;
	return v;
}

struct ir_value bpf_ir_value_const64(s64 val)
{
	struct ir_value v = value_base();
	v.type = IR_VALUE_CONSTANT;
	v.data.constant_d = val;
	v.const_type = IR_ALU_64;
	return v;
}

struct ir_value bpf_ir_value_const32_rawoff(s32 val)
{
	struct ir_value v = value_base();
	v.type = IR_VALUE_CONSTANT_RAWOFF;
	v.data.constant_d = val;
	v.const_type = IR_ALU_32;
	return v;
}

struct ir_value bpf_ir_value_const64_rawoff(s64 val)
{
	struct ir_value v = value_base();
	v.type = IR_VALUE_CONSTANT_RAWOFF;
	v.data.constant_d = val;
	v.const_type = IR_ALU_64;
	return v;
}

struct ir_address_value bpf_ir_addr_val(struct ir_value value, s16 offset)
{
	return (struct ir_address_value){ .value = value,
					  .offset = offset,
					  .offset_type = IR_VALUE_CONSTANT };
}

struct ir_value bpf_ir_value_stack_ptr(struct ir_function *fun)
{
	return bpf_ir_value_insn(fun->sp);
}

void bpf_ir_change_value(struct bpf_ir_env *env, struct ir_insn *insn,
			 struct ir_value *old, struct ir_value new)
{
	bpf_ir_val_remove_user(*old, insn);
	*old = new;
	bpf_ir_val_add_user(env, new, insn);
}

// Const expr

s64 evaluate_const_expr(struct ir_constant_value *ctx, s64 *built_in_const)
{
	if (ctx) {
		return 0;
	}
	if (ctx->cvty == IR_CONST_VALUE_NUM) {
		return ctx->num;
	} else if (ctx->cvty == IR_CONST_VALUE_CONSTEXPR) {
		struct ir_constant_expr expr = *ctx->expr;
		switch (expr.cety) {
		case IR_CONSTEXPR_ADD:
			return evaluate_const_expr(expr.v0, built_in_const) +
			       evaluate_const_expr(expr.v1, built_in_const);
		case IR_CONSTEXPR_MUL:
			return evaluate_const_expr(expr.v0, built_in_const) *
			       evaluate_const_expr(expr.v1, built_in_const);
		case IR_CONSTEXPR_DIV:
			return evaluate_const_expr(expr.v0, built_in_const) /
			       evaluate_const_expr(expr.v1, built_in_const);
		default:
			CRITICAL("Error");
		}
	} else {
		return built_in_const[(size_t)ctx->cvty];
	}
}

static void erase_const(struct ir_constant_value *ctx){
	if (!ctx) {
		return;
	}
	// Clean up resources
	if (ctx->cvty == IR_CONST_VALUE_CONSTEXPR) {
		bpf_ir_erase_constexpr(ctx->expr);
	}
	free_proto(ctx);
}

// Clean up the constant expression
void bpf_ir_erase_constexpr(struct ir_constant_expr *expr){
	if(!expr){
		return;
	}
	erase_const(expr->v0);
	erase_const(expr->v1);
	free_proto(expr);
}