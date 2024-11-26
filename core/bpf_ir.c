// SPDX-License-Identifier: GPL-2.0-only

#include <linux/bpf_common.h>
#include <linux/bpf_ir.h>

static const s8 helper_func_arg_num[] = {
	[1] = 2, // map_lookup_elem
	[2] = 4, // map_update_elem
	[3] = 2, // map_delete_elem
	[4] = 3, // bpf_probe_read
	[5] = 0, // ktime_get_ns
	[6] = -1, // trace_printk // 5 may cause an error. May not have 5 arguments
	[7] = 0, // get_prandom_u32
	[8] = 0, // get_smp_processor_id
	[9] = 5, // skb_store_bytes
	[10] = 5, // l3_csum_replace
	[11] = 5, // l4_csum_replace
	[12] = 3, // tail_call
	[13] = 3, // clone_redirect
	[14] = 0, // get_current_pid_tgid
	[15] = 0, // get_current_uid_gid
	[16] = 2, // get_current_comm
	[17] = 1, // get_cgroup_classid
	[18] = 3, // skb_vlan_push
	[19] = 1, // skb_vlan_pop
	[20] = 4, // skb_get_tunnel_key
	[21] = 4, // skb_set_tunnel_key
	[22] = 2, // perf_event_read
	[23] = 2, // redirect
	[24] = 1, // get_route_realm
	[25] = 5, // perf_event_output
	[26] = 4, // skb_load_bytes
	[27] = 3, // get_stackid
	[28] = 5, // csum_diff
	[29] = 3, // skb_get_tunnel_opt
	[30] = 3, // skb_set_tunnel_opt
	[31] = 3, // skb_change_proto
	[32] = 2, // skb_change_type
	[33] = 3, // skb_under_cgroup
	[34] = 1, // get_hash_recalc
	[35] = 0, // get_current_task
	[36] = 3, // probe_write_user
	[37] = 2, // current_task_under_cgroup
	[38] = 3, // skb_change_tail
	[39] = 2, // skb_pull_data
	[40] = 2, // csum_update
	[41] = 1, // set_hash_invalid
	[42] = 0, // get_numa_node_id
	[43] = 3, // skb_change_head
	[44] = 2, // xdp_adjust_head
	[45] = 3, // bpf_probe_read_str
	[46] = 1, // get_socket_cookie
	[47] = 1, // get_socket_uid
	[48] = 2, // set_hash
	[49] = 5, // setsockopt
	[50] = 4, // skb_adjust_room
	[51] = 3, // bpf_redirect_map
	[52] = 4, // sk_redirect_map
	[53] = 4, // sock_map_update
	[54] = 2, // xdp_adjust_meta
	[55] = 4, // perf_event_read_value
	[56] = 3, // perf_prog_read_value
	[57] = 5, // getsockopt
	[58] = 2, // override_return
	[59] = 2, // sock_ops_cb_flags_set
	[60] = 4, // msg_redirect_map
	[61] = 2, // msg_apply_bytes
	[62] = 2, // msg_cork_bytes
	[63] = 4, // msg_pull_data
	[64] = 3, // bind
	[65] = 2, // xdp_adjust_tail
	[66] = 5, // skb_get_xfrm_state
	[67] = 4, // get_stack
	[68] = 5, // skb_load_bytes_relative
	[69] = 4, // fib_lookup
	[70] = 4, // sock_hash_update
	[71] = 4, // msg_redirect_hash
	[72] = 4, // sk_redirect_hash
	[73] = 4, // lwt_push_encap
	[74] = 4, // lwt_seg6_store_bytes
	[75] = 3, // lwt_seg6_adjust_srh
	[76] = 4, // lwt_seg6_action
	[77] = 1, // rc_repeat
	[78] = 4, // rc_keydown
	[79] = 1, // skb_cgroup_id
	[80] = 0, // get_current_cgroup_id
	[81] = 2, // get_local_storage
	[82] = 4, // sk_select_reuseport
	[83] = 2, // skb_ancestor_cgroup_id
	[84] = 5, // sk_lookup_tcp
	[85] = 5, // sk_lookup_udp
	[86] = 1, // sk_release
	[87] = 3, // map_push_elem
	[88] = 2, // map_pop_elem
	[89] = 2, // map_peek_elem
	[90] = 4, // msg_push_data
	[91] = 4, // msg_pop_data
	[92] = 3, // rc_pointer_rel
	[93] = 1, // spin_lock
	[94] = 1, // spin_unlock
	[95] = 1, // sk_fullsock
	[96] = 1, // tcp_sock
	[97] = 1, // skb_ecn_set_ce
	[98] = 1, // get_listener_sock
	[99] = 5, // skc_lookup_tcp
	[100] = 5, // tcp_check_syncookie
	[101] = 4, // sysctl_get_name
	[102] = 3, // sysctl_get_current_value
	[103] = 3, // sysctl_get_new_value
	[104] = 3, // sysctl_set_new_value
	[105] = 4, // strtol
	[106] = 4, // strtoul
	[107] = 5, // sk_storage_get
	[108] = 2, // sk_storage_delete
	[109] = 1, // send_signal
	[110] = 5, // tcp_gen_syncookie
	[111] = 5, // skb_output
	[112] = 3, // probe_read_user
	[113] = 3, // probe_read_kernel
	[114] = 3, // probe_read_user_str
	[115] = 3, // probe_read_kernel_str
	[116] = 2, // tcp_send_ack
	[117] = 1, // send_signal_thread
	[118] = 0, // jiffies64
	[119] = 4, // read_branch_records
	[120] = 4, // get_ns_current_pid_tgid
	[121] = 5, // xdp_output
	[122] = 1, // get_netns_cookie
	[123] = 1, // get_current_ancestor_cgroup_id
	[124] = 3, // sk_assign
	[125] = 0, // ktime_get_boot_ns
	[126] = 5, // seq_printf
	[127] = 3, // seq_write
	[128] = 1, // sk_cgroup_id
	[129] = 2, // sk_ancestor_cgroup_id
	[130] = 4, // ringbuf_output
	[131] = 3, // ringbuf_reserve
	[132] = 2, // ringbuf_submit
	[133] = 2, // ringbuf_discard
	[134] = 2, // ringbuf_query
	[135] = 2, // csum_level
	[136] = 1, // skc_to_tcp6_sock
	[137] = 1, // skc_to_tcp_sock
	[138] = 1, // skc_to_tcp_timewait_sock
	[139] = 1, // skc_to_tcp_request_sock
	[140] = 1, // skc_to_udp6_sock
	[141] = 4, // get_task_stack
	[142] = 4, // load_hdr_opt
	[143] = 4, // store_hdr_opt
	[144] = 3, // reserve_hdr_opt
	[145] = 5, // inode_storage_get
	[146] = 2, // inode_storage_delete
	[147] = 3, // d_path
	[148] = 3, // copy_from_user
	[149] = 5, // snprintf_btf
	[150] = 4, // seq_printf_btf
	[151] = 1, // skb_cgroup_classid
	[152] = 4, // redirect_neigh
	[153] = 2, // per_cpu_ptr
	[154] = 1, // this_cpu_ptr
	[155] = 2, // redirect_peer
	[156] = 5, // task_storage_get
	[157] = 2, // task_storage_delete
	[158] = 0, // get_current_task_btf
	[159] = 2, // bprm_opts_set
	[160] = 0, // ktime_get_coarse_ns
	[161] = 3, // ima_inode_hash
	[162] = 1, // sock_from_file
	[163] = 5, // check_mtu
	[164] = 4, // for_each_map_elem
	[165] = 5, // snprintf
	[166] = 3, // sys_bpf
	[167] = 4, // btf_find_by_name_kind
	[168] = 1, // sys_close
	[169] = 3, // timer_init
	[170] = 3, // timer_set_callback
	[171] = 3, // timer_start
	[172] = 1, // timer_cancel
	[173] = 1, // get_func_ip
	[174] = 1, // get_attach_cookie
	[175] = 1, // task_pt_regs
	[176] = 3, // get_branch_snapshot
	[177] = 4, // trace_vprintk
	[178] = 1, // skc_to_unix_sock
	[179] = 4, // kallsyms_lookup_name
	[180] = 5, // find_vma
	[181] = 4, // loop
	[182] = 3, // strncmp
	[183] = 3, // get_func_arg
	[184] = 2, // bpf_get_func_ret
	[185] = 1, // bpf_get_func_arg_cnt
	[186] = 0, // get_retval
	[187] = 1, // set_retval
	[188] = 1, // xdp_get_buff_len
	[189] = 4, // xdp_load_bytes
	[190] = 4, // xdp_store_bytes
	[191] = 5, // copy_from_user_task
	[192] = 3, // skb_set_tstamp
	[193] = 3, // ima_file_hash
	[194] = 2, // kptr_xchg
	[195] = 3, // map_lookup_percpu_elem
	[196] = 1, // skc_to_mptcp_sock
	[197] = 4, // dynptr_from_mem
	[198] = 4, // ringbuf_reserve_dynptr
	[199] = 2, // ringbuf_submit_dynptr
	[200] = 2, // ringbuf_discard_dynptr
	[201] = 5, // dynptr_read
	[202] = 5, // dynptr_write
	[203] = 3, // dynptr_data
	[204] = 3, // tcp_raw_gen_syncookie_ipv4
	[205] = 3, // tcp_raw_gen_syncookie_ipv6
	[206] = 2, // tcp_raw_check_syncookie_ipv4
	[207] = 2, // tcp_raw_check_syncookie_ipv6
	[208] = 0, // ktime_get_tai_ns
	[209] = 4, // user_ringbuf_drain
	[210] = 5, // cgrp_storage_get
	[211] = 2, // cgrp_storage_delete
};

// All function passes
static const struct function_pass pre_passes[] = {
	DEF_FUNC_PASS(remove_trivial_phi, "remove_trivial_phi", true),
};

static const struct function_pass post_passes[] = {
	DEF_FUNC_PASS(bpf_ir_div_by_zero, "div_by_zero", false),
	DEF_FUNC_PASS(msan, "msan", false),
	DEF_FUNC_PASS(add_counter, "add_counter", false),
	/* CG Preparation Passes */
	DEF_NON_OVERRIDE_FUNC_PASS(translate_throw, "translate_throw"),
	DEF_NON_OVERRIDE_FUNC_PASS(bpf_ir_optimize_code_compaction,
				   "optimize_compaction"),
	DEF_NON_OVERRIDE_FUNC_PASS(bpf_ir_optimize_ir, "optimize_ir"),
	DEF_NON_OVERRIDE_FUNC_PASS(bpf_ir_cg_change_fun_arg, "change_fun_arg"),
	DEF_NON_OVERRIDE_FUNC_PASS(bpf_ir_cg_change_call_pre_cg, "change_call"),
	DEF_NON_OVERRIDE_FUNC_PASS(bpf_ir_cg_add_stack_offset_pre_cg,
				   "add_stack_offset"),
	DEF_NON_OVERRIDE_FUNC_PASS(bpr_ir_cg_to_cssa, "to_cssa"),
};

static void write_variable(struct bpf_ir_env *env,
			   struct ssa_transform_env *tenv, u8 reg,
			   struct pre_ir_basic_block *bb, struct ir_value val);

static struct ir_value read_variable(struct bpf_ir_env *env,
				     struct ssa_transform_env *tenv, u8 reg,
				     struct pre_ir_basic_block *bb);

static struct ir_insn *add_phi_operands(struct bpf_ir_env *env,
					struct ssa_transform_env *tenv, u8 reg,
					struct ir_insn *insn);

static void add_user(struct bpf_ir_env *env, struct ir_insn *user,
		     struct ir_value val);

static int compare_num(const void *a, const void *b)
{
	struct bb_entrance_info *as = (struct bb_entrance_info *)a;
	struct bb_entrance_info *bs = (struct bb_entrance_info *)b;
	if (as->entrance > bs->entrance) {
		return 1;
	}
	if (as->entrance < bs->entrance) {
		return -1;
	}
	return 0;
}

static bool is_raw_insn_breakpoint(u8 code)
{
	// exit, jmp (not call) is breakpoint
	if (BPF_CLASS(code) == BPF_JMP || BPF_CLASS(code) == BPF_JMP32) {
		if (BPF_OP(code) != BPF_CALL) {
			return true;
		} else {
			// call is not a breakpoint
			return false;
		}
	}
	return false;
}

// Add current_pos --> entrance_pos in bb_entrances
static void add_entrance_info(struct bpf_ir_env *env,
			      const struct bpf_insn *insns,
			      struct array *bb_entrances, size_t entrance_pos,
			      size_t current_pos)
{
	for (size_t i = 0; i < bb_entrances->num_elem; ++i) {
		struct bb_entrance_info *entry =
			((struct bb_entrance_info *)(bb_entrances->data)) + i;
		if (entry->entrance == entrance_pos) {
			// Already has this entrance, add a pred
			bpf_ir_array_push_unique(env, &entry->bb->preds,
						 &current_pos);
			return;
		}
	}
	// New entrance
	struct array preds;
	INIT_ARRAY(&preds, size_t);
	if (entrance_pos >= 1) {
		size_t last_pos = entrance_pos - 1;
		u8 code = insns[last_pos].code;
		if (!is_raw_insn_breakpoint(code)) { // Error!
			// Breaking point
			// rx = ...
			// BB Entrance
			// ==> Add preds
			bpf_ir_array_push_unique(env, &preds, &last_pos);
		}
	}
	bpf_ir_array_push_unique(env, &preds, &current_pos);
	struct bb_entrance_info new_bb;
	new_bb.entrance = entrance_pos;
	SAFE_MALLOC(new_bb.bb, sizeof(struct pre_ir_basic_block));
	new_bb.bb->preds = preds;
	bpf_ir_array_push(env, bb_entrances, &new_bb);
}

// Return the parent BB of a instruction
static struct pre_ir_basic_block *get_bb_parent(struct array *bb_entrance,
						size_t pos)
{
	size_t bb_id = 0;
	struct bb_entrance_info *bbs =
		(struct bb_entrance_info *)(bb_entrance->data);
	for (size_t i = 1; i < bb_entrance->num_elem; ++i) {
		struct bb_entrance_info *entry = bbs + i;
		if (entry->entrance <= pos) {
			bb_id++;
		} else {
			break;
		}
	}
	return bbs[bb_id].bb;
}

static void init_entrance_info(struct bpf_ir_env *env,
			       struct array *bb_entrances, size_t entrance_pos)
{
	for (size_t i = 0; i < bb_entrances->num_elem; ++i) {
		struct bb_entrance_info *entry =
			((struct bb_entrance_info *)(bb_entrances->data)) + i;
		if (entry->entrance == entrance_pos) {
			// Already has this entrance
			return;
		}
	}
	// New entrance
	struct array preds;
	INIT_ARRAY(&preds, size_t);
	struct bb_entrance_info new_bb;
	new_bb.entrance = entrance_pos;
	SAFE_MALLOC(new_bb.bb, sizeof(struct pre_ir_basic_block));
	new_bb.bb->preds = preds;
	bpf_ir_array_push(env, bb_entrances, &new_bb);
}

static void init_ir_bb(struct bpf_ir_env *env, struct pre_ir_basic_block *bb)
{
	bb->ir_bb = bpf_ir_init_bb_raw();
	if (!bb->ir_bb) {
		env->err = -ENOMEM;
		return;
	}
	bb->ir_bb->_visited = 0;
	bb->ir_bb->user_data = bb;
	for (u8 i = 0; i < MAX_BPF_REG; ++i) {
		bb->incompletePhis[i] = NULL;
	}
}

static s64 to_s64(s32 imm, s32 next_imm)
{
	u64 imml = (u64)imm & 0xFFFFFFFF;
	return ((s64)next_imm << 32) | imml;
}

static void gen_bb(struct bpf_ir_env *env, struct bb_info *ret,
		   const struct bpf_insn *insns, size_t len)
{
	struct array bb_entrance;
	INIT_ARRAY(&bb_entrance, struct bb_entrance_info);
	// First, scan the code to find all the BB entrances
	for (size_t i = 0; i < len; ++i) {
		struct bpf_insn insn = insns[i];
		u8 code = insn.code;
		if (BPF_CLASS(code) == BPF_JMP ||
		    BPF_CLASS(code) == BPF_JMP32) {
			if (BPF_OP(code) == BPF_JA) {
				// Direct Jump
				size_t pos = 0;
				if (BPF_CLASS(code) == BPF_JMP) {
					// JMP class (64 bits)
					// Add offset
					pos = (s16)i + insn.off + 1;
				} else {
					// Impossible by spec
					RAISE_ERROR(
						"BPF_JA only allows JMP class");
				}
				// Add to bb entrance
				// This is one-way control flow
				add_entrance_info(env, insns, &bb_entrance, pos,
						  i);
				CHECK_ERR();
			}
			if ((BPF_OP(code) >= BPF_JEQ &&
			     BPF_OP(code) <= BPF_JSGE) ||
			    (BPF_OP(code) >= BPF_JLT &&
			     BPF_OP(code) <= BPF_JSLE)) {
				// Add offset
				size_t pos = (s16)i + insn.off + 1;
				add_entrance_info(env, insns, &bb_entrance, pos,
						  i);
				CHECK_ERR();
				add_entrance_info(env, insns, &bb_entrance,
						  i + 1, i);
				CHECK_ERR();
			}
			if (BPF_OP(code) == BPF_EXIT) {
				// BPF_EXIT
				if (i + 1 < len) {
					// Not the last instruction
					init_entrance_info(env, &bb_entrance,
							   i + 1);
					CHECK_ERR();
				}
			}
		}
	}

	// Create the first BB (entry block)
	struct bb_entrance_info bb_entry_info;
	bb_entry_info.entrance = 0;
	SAFE_MALLOC(bb_entry_info.bb, sizeof(struct pre_ir_basic_block));
	bb_entry_info.bb->preds = bpf_ir_array_null();
	bpf_ir_array_push(env, &bb_entrance, &bb_entry_info);

	// Sort the BBs
	qsort(bb_entrance.data, bb_entrance.num_elem, bb_entrance.elem_size,
	      &compare_num);
	// Generate real basic blocks

	struct bb_entrance_info *all_bbs =
		((struct bb_entrance_info *)(bb_entrance.data));

	// Print the BB
	// for (size_t i = 0; i < bb_entrance.num_elem; ++i) {
	// 	struct bb_entrance_info entry = all_bbs[i];
	// PRINT_LOG_DEBUG(env, "%ld: %ld\n", entry.entrance,
	// 	  entry.bb->preds.num_elem);
	// }

	// Init preds
	for (size_t i = 0; i < bb_entrance.num_elem; ++i) {
		struct bb_entrance_info *entry = all_bbs + i;
		struct pre_ir_basic_block *real_bb = entry->bb;
		real_bb->id = i;
		INIT_ARRAY(&real_bb->succs, struct pre_ir_basic_block *);
		real_bb->visited = 0;
		real_bb->pre_insns = NULL;
		real_bb->start_pos = entry->entrance;
		real_bb->end_pos = i + 1 < bb_entrance.num_elem ?
					   all_bbs[i + 1].entrance :
					   len;
		real_bb->filled = 0;
		real_bb->sealed = 0;
		real_bb->ir_bb = NULL;
	}

	// Allocate instructions
	for (size_t i = 0; i < bb_entrance.num_elem; ++i) {
		struct pre_ir_basic_block *real_bb = all_bbs[i].bb;
		// PRINT_LOG_DEBUG(env, "BB Alloc: [%zu, %zu)\n", real_bb->start_pos,
		// 	  real_bb->end_pos);
		SAFE_MALLOC(real_bb->pre_insns,
			    sizeof(struct pre_ir_insn) *
				    (real_bb->end_pos - real_bb->start_pos));
		size_t bb_pos = 0;
		for (size_t pos = real_bb->start_pos; pos < real_bb->end_pos;
		     ++pos, ++bb_pos) {
			struct bpf_insn insn = insns[pos];
			struct pre_ir_insn new_insn;
			new_insn.opcode = insn.code;
			new_insn.src_reg = insn.src_reg;
			new_insn.dst_reg = insn.dst_reg;
			new_insn.imm = insn.imm;
			new_insn.it = IMM;
			new_insn.imm64 = (u64)insn.imm & 0xFFFFFFFF;
			new_insn.off = insn.off;
			new_insn.pos = pos;
			if (pos + 1 < real_bb->end_pos &&
			    insns[pos + 1].code == 0) {
				new_insn.imm64 =
					to_s64(insn.imm, insns[pos + 1].imm);
				new_insn.it = IMM64;
				pos++;
			}
			real_bb->pre_insns[bb_pos] = new_insn;
		}
		real_bb->len = bb_pos;
	}
	for (size_t i = 0; i < bb_entrance.num_elem; ++i) {
		struct bb_entrance_info *entry = all_bbs + i;

		struct array preds = entry->bb->preds;
		struct array new_preds;
		INIT_ARRAY(&new_preds, struct pre_ir_basic_block *);
		for (size_t j = 0; j < preds.num_elem; ++j) {
			size_t pred_pos = ((size_t *)(preds.data))[j];
			// Get the real parent BB
			struct pre_ir_basic_block *parent_bb =
				get_bb_parent(&bb_entrance, pred_pos);
			// We push the address to the array
			bpf_ir_array_push(env, &new_preds, &parent_bb);
			// Add entry->bb to the succ of parent_bb
			bpf_ir_array_push(env, &parent_bb->succs, &entry->bb);
		}
		bpf_ir_array_free(&preds);
		entry->bb->preds = new_preds;
	}
	// Return the entry BB
	ret->entry = all_bbs[0].bb;
	ret->all_bbs = bb_entrance;
}

static void print_pre_ir_cfg(struct bpf_ir_env *env,
			     struct pre_ir_basic_block *bb)
{
	if (bb->visited) {
		return;
	}
	bb->visited = 1;
	PRINT_LOG_DEBUG(env, "BB %ld:\n", bb->id);
	for (size_t i = 0; i < bb->len; ++i) {
		struct pre_ir_insn insn = bb->pre_insns[i];
		PRINT_LOG_DEBUG(env, "%x %x %llx\n", insn.opcode, insn.imm,
				insn.imm64);
	}
	PRINT_LOG_DEBUG(env, "preds (%ld): ", bb->preds.num_elem);
	for (size_t i = 0; i < bb->preds.num_elem; ++i) {
		struct pre_ir_basic_block *pred =
			((struct pre_ir_basic_block **)(bb->preds.data))[i];
		PRINT_LOG_DEBUG(env, "%ld ", pred->id);
	}
	PRINT_LOG_DEBUG(env, "\nsuccs (%ld): ", bb->succs.num_elem);
	for (size_t i = 0; i < bb->succs.num_elem; ++i) {
		struct pre_ir_basic_block *succ =
			((struct pre_ir_basic_block **)(bb->succs.data))[i];
		PRINT_LOG_DEBUG(env, "%ld ", succ->id);
	}
	PRINT_LOG_DEBUG(env, "\n\n");
	for (size_t i = 0; i < bb->succs.num_elem; ++i) {
		struct pre_ir_basic_block *succ =
			((struct pre_ir_basic_block **)(bb->succs.data))[i];
		print_pre_ir_cfg(env, succ);
	}
}

static void init_tenv(struct bpf_ir_env *env, struct ssa_transform_env *tenv,
		      struct bb_info info)
{
	for (size_t i = 0; i < MAX_BPF_REG; ++i) {
		INIT_ARRAY(&tenv->currentDef[i], struct bb_val);
	}
	tenv->info = info;
	// Initialize SP
	SAFE_MALLOC(tenv->sp, sizeof(struct ir_insn));
	INIT_ARRAY(&tenv->sp->users, struct ir_insn *);
	tenv->sp->op = IR_INSN_REG;
	tenv->sp->value_num = 0;
	tenv->sp->user_data = NULL;
	tenv->sp->parent_bb = NULL;
	tenv->sp->reg_id = BPF_REG_10;
	write_variable(env, tenv, BPF_REG_10, NULL,
		       bpf_ir_value_insn(tenv->sp));
	// Initialize function argument
	for (u8 i = 0; i < MAX_FUNC_ARG; ++i) {
		SAFE_MALLOC(tenv->function_arg[i], sizeof(struct ir_insn));

		INIT_ARRAY(&tenv->function_arg[i]->users, struct ir_insn *);
		tenv->function_arg[i]->op = IR_INSN_FUNCTIONARG;
		tenv->function_arg[i]->fun_arg_id = i;
		tenv->function_arg[i]->user_data = NULL;
		tenv->function_arg[i]->value_num = 0;
		write_variable(env, tenv, BPF_REG_1 + i, NULL,
			       bpf_ir_value_insn(tenv->function_arg[i]));
	}
}

static void seal_block(struct bpf_ir_env *env, struct ssa_transform_env *tenv,
		       struct pre_ir_basic_block *bb)
{
	// Seal a BB
	for (u8 i = 0; i < MAX_BPF_REG; ++i) {
		if (bb->incompletePhis[i]) {
			add_phi_operands(env, tenv, i, bb->incompletePhis[i]);
		}
	}
	bb->sealed = 1;
}

static void write_variable(struct bpf_ir_env *env,
			   struct ssa_transform_env *tenv, u8 reg,
			   struct pre_ir_basic_block *bb, struct ir_value val)
{
	// if (reg >= MAX_BPF_REG - 1) {
	// 	// Stack pointer is read-only
	// 	CRITICAL("Error");
	// }
	// Write a variable to a BB
	struct array *currentDef = &tenv->currentDef[reg];
	// Traverse the array to find if there exists a value in the same BB
	for (size_t i = 0; i < currentDef->num_elem; ++i) {
		struct bb_val *bval = ((struct bb_val *)(currentDef->data)) + i;
		if (bval->bb == bb) {
			// Found
			bval->val = val;
			return;
		}
	}
	// Not found
	struct bb_val new_val;
	new_val.bb = bb;
	new_val.val = val;
	bpf_ir_array_push(env, currentDef, &new_val);
}

static struct ir_insn *add_phi_operands(struct bpf_ir_env *env,
					struct ssa_transform_env *tenv, u8 reg,
					struct ir_insn *insn)
{
	// insn must be a (initialized) PHI instruction
	if (insn->op != IR_INSN_PHI) {
		CRITICAL("Not a PHI node");
	}
	for (size_t i = 0; i < insn->parent_bb->preds.num_elem; ++i) {
		struct ir_basic_block *pred =
			((struct ir_basic_block **)(insn->parent_bb->preds
							    .data))[i];
		struct phi_value phi;
		phi.bb = pred;
		phi.value = read_variable(
			env, tenv, reg,
			(struct pre_ir_basic_block *)pred->user_data);
		add_user(env, insn, phi.value);
		bpf_ir_array_push(env, &pred->users, &insn);
		bpf_ir_array_push(env, &insn->phi, &phi);
	}
	return insn;
}

static struct ir_insn *create_insn(void)
{
	struct ir_insn *insn = malloc_proto(sizeof(struct ir_insn));
	if (!insn) {
		return NULL;
	}
	INIT_ARRAY(&insn->users, struct ir_insn *);
	// Setting the default values
	insn->alu_op = IR_ALU_UNKNOWN;
	insn->vr_type = IR_VR_TYPE_UNKNOWN;
	insn->value_num = 0;
	insn->raw_pos.valid = false;
	return insn;
}

static struct ir_insn *create_insn_back(struct ir_basic_block *bb)
{
	struct ir_insn *insn = create_insn();
	insn->parent_bb = bb;
	list_add_tail(&insn->list_ptr, &bb->ir_insn_head);
	return insn;
}

static struct ir_insn *create_insn_front(struct ir_basic_block *bb)
{
	struct ir_insn *insn = create_insn();
	insn->parent_bb = bb;
	list_add(&insn->list_ptr, &bb->ir_insn_head);
	return insn;
}

static struct ir_value read_variable_recursive(struct bpf_ir_env *env,
					       struct ssa_transform_env *tenv,
					       u8 reg,
					       struct pre_ir_basic_block *bb)
{
	struct ir_value val;
	if (!bb->sealed) {
		// Incomplete CFG
		struct ir_insn *new_insn = create_insn_front(bb->ir_bb);
		new_insn->op = IR_INSN_PHI;
		INIT_ARRAY(&new_insn->phi, struct phi_value);
		bb->incompletePhis[reg] = new_insn;
		val = bpf_ir_value_insn(new_insn);
	} else if (bb->preds.num_elem == 1) {
		val = read_variable(
			env, tenv, reg,
			((struct pre_ir_basic_block **)(bb->preds.data))[0]);
	} else {
		struct ir_insn *new_insn = create_insn_front(bb->ir_bb);
		new_insn->op = IR_INSN_PHI;
		INIT_ARRAY(&new_insn->phi, struct phi_value);
		val = bpf_ir_value_insn(new_insn);
		write_variable(env, tenv, reg, bb, val);
		new_insn = add_phi_operands(env, tenv, reg, new_insn);
		val = bpf_ir_value_insn(new_insn);
	}
	write_variable(env, tenv, reg, bb, val);
	return val;
}

static bool is_variable_defined(struct ssa_transform_env *tenv, u8 reg,
				struct pre_ir_basic_block *bb)
{
	struct bb_val *pos;

	array_for(pos, tenv->currentDef[reg])
	{
		if (pos->bb == bb) {
			return true;
		}
	}
	return false;
}

static struct ir_value read_variable(struct bpf_ir_env *env,
				     struct ssa_transform_env *tenv, u8 reg,
				     struct pre_ir_basic_block *bb)
{
	// Read a variable from a BB
	if (reg == BPF_REG_10) {
		// Stack pointer
		return bpf_ir_value_insn(tenv->sp);
	}
	struct array *currentDef = &tenv->currentDef[reg];
	for (size_t i = 0; i < currentDef->num_elem; ++i) {
		struct bb_val *bval = ((struct bb_val *)(currentDef->data)) + i;
		if (bval->bb == bb) {
			// Found
			return bval->val;
		}
	}
	if (bb == tenv->info.entry) {
		// Entry block, has definitions for r1 to r5
		if (reg > BPF_REG_0 && reg <= MAX_FUNC_ARG) {
			return bpf_ir_value_insn(tenv->function_arg[reg - 1]);
		} else {
			// Invalid Program!
			// Should throw an exception here
			PRINT_LOG_ERROR(env,
					"Finding def for r%d in entry block\n",
					reg);
			RAISE_ERROR_RET("Invalid program detected!",
					bpf_ir_value_undef());
		}
	}
	// Not found
	return read_variable_recursive(env, tenv, reg, bb);
}

static enum ir_vr_type to_ir_ld_u(u8 size)
{
	switch (size) {
	case BPF_W:
		return IR_VR_TYPE_32;
	case BPF_H:
		return IR_VR_TYPE_16;
	case BPF_B:
		return IR_VR_TYPE_8;
	case BPF_DW:
		return IR_VR_TYPE_64;
	default:
		CRITICAL("Error");
	}
}

u32 bpf_ir_sizeof_vr_type(enum ir_vr_type type)
{
	switch (type) {
	case IR_VR_TYPE_32:
		return 4;
	case IR_VR_TYPE_16:
		return 2;
	case IR_VR_TYPE_8:
		return 1;
	case IR_VR_TYPE_64:
		return 8;
	default:
		CRITICAL("Error");
	}
}

// User uses val
static void add_user(struct bpf_ir_env *env, struct ir_insn *user,
		     struct ir_value val)
{
	if (val.type == IR_VALUE_INSN) {
		bpf_ir_array_push_unique(env, &val.data.insn_d->users, &user);
	}
}

/**
    Initialize the IR BBs

    Allocate memory and set the preds and succs.
 */
static void init_ir_bbs(struct bpf_ir_env *env, struct ssa_transform_env *tenv)
{
	for (size_t i = 0; i < tenv->info.all_bbs.num_elem; ++i) {
		struct pre_ir_basic_block *bb = ((
			struct bb_entrance_info *)(tenv->info.all_bbs.data))[i]
							.bb;
		init_ir_bb(env, bb);
		CHECK_ERR();
	}
	// Set the preds and succs
	for (size_t i = 0; i < tenv->info.all_bbs.num_elem; ++i) {
		struct pre_ir_basic_block *bb = ((
			struct bb_entrance_info *)(tenv->info.all_bbs.data))[i]
							.bb;
		struct ir_basic_block *irbb = bb->ir_bb;
		for (size_t j = 0; j < bb->preds.num_elem; ++j) {
			struct pre_ir_basic_block *pred =
				((struct pre_ir_basic_block *
					  *)(bb->preds.data))[j];
			bpf_ir_array_push(env, &irbb->preds, &pred->ir_bb);
		}
		for (size_t j = 0; j < bb->succs.num_elem; ++j) {
			struct pre_ir_basic_block *succ =
				((struct pre_ir_basic_block *
					  *)(bb->succs.data))[j];
			bpf_ir_array_push(env, &irbb->succs, &succ->ir_bb);
		}
	}
}

static struct ir_basic_block *
get_ir_bb_from_position(struct ssa_transform_env *tenv, size_t pos)
{
	// Iterate through all the BBs
	for (size_t i = 0; i < tenv->info.all_bbs.num_elem; ++i) {
		struct bb_entrance_info *info = &((
			struct bb_entrance_info *)(tenv->info.all_bbs.data))[i];
		if (info->entrance == pos) {
			return info->bb->ir_bb;
		}
	}
	CRITICAL("Error");
}

static void set_insn_raw_pos(struct ir_insn *insn, size_t pos)
{
	insn->raw_pos.valid = true;
	insn->raw_pos.pos = pos;
	insn->raw_pos.pos_t = IR_RAW_POS_INSN;
}

static void set_value_raw_pos(struct ir_value *val, size_t pos,
			      enum ir_raw_pos_type ty)
{
	val->raw_pos.valid = true;
	val->raw_pos.pos = pos;
	val->raw_pos.pos_t = ty;
}

static struct ir_value get_src_value(struct bpf_ir_env *env,
				     struct ssa_transform_env *tenv,
				     struct pre_ir_basic_block *bb,
				     struct pre_ir_insn insn)
{
	u8 code = insn.opcode;
	if (BPF_SRC(code) == BPF_K) {
		struct ir_value v = bpf_ir_value_const32(insn.imm);
		set_value_raw_pos(&v, insn.pos, IR_RAW_POS_IMM);
		return v;
	} else if (BPF_SRC(code) == BPF_X) {
		struct ir_value v = read_variable(env, tenv, insn.src_reg, bb);
		set_value_raw_pos(&v, insn.pos, IR_RAW_POS_SRC);
		return v;
	} else {
		CRITICAL("Error");
	}
}

static struct ir_insn *create_alu_nonbin(struct bpf_ir_env *env,
					 struct ir_basic_block *bb,
					 struct ir_value val1,
					 enum ir_insn_type ty,
					 enum ir_alu_op_type alu_ty)
{
	struct ir_insn *new_insn = create_insn_back(bb);
	new_insn->op = ty;
	new_insn->values[0] = val1;
	new_insn->value_num = 1;
	new_insn->alu_op = alu_ty;
	add_user(env, new_insn, new_insn->values[0]);
	return new_insn;
}

static struct ir_insn *
create_alu_bin(struct bpf_ir_env *env, struct ir_basic_block *bb,
	       struct ir_value val1, struct ir_value val2, enum ir_insn_type ty,
	       enum ir_alu_op_type alu_ty)
{
	struct ir_insn *new_insn = create_insn_back(bb);
	new_insn->op = ty;
	new_insn->values[0] = val1;
	new_insn->values[1] = val2;
	new_insn->value_num = 2;
	new_insn->alu_op = alu_ty;
	add_user(env, new_insn, new_insn->values[0]);
	add_user(env, new_insn, new_insn->values[1]);
	return new_insn;
}

static void alu_write_bin(struct bpf_ir_env *env,
			  struct ssa_transform_env *tenv, enum ir_insn_type ty,
			  struct pre_ir_insn insn,
			  struct pre_ir_basic_block *bb,
			  enum ir_alu_op_type alu_ty)
{
	struct ir_insn *new_insn = create_alu_bin(
		env, bb->ir_bb, read_variable(env, tenv, insn.dst_reg, bb),
		get_src_value(env, tenv, bb, insn), ty, alu_ty);
	struct ir_value v = bpf_ir_value_insn(new_insn);
	set_insn_raw_pos(new_insn, insn.pos);
	set_value_raw_pos(&v, insn.pos, IR_RAW_POS_INSN);
	set_value_raw_pos(&new_insn->values[0], insn.pos, IR_RAW_POS_DST);
	write_variable(env, tenv, insn.dst_reg, bb, v);
}

static void bpf_neg_write(struct bpf_ir_env *env,
			  struct ssa_transform_env *tenv,
			  struct pre_ir_insn insn,
			  struct pre_ir_basic_block *bb,
			  enum ir_alu_op_type alu_ty)
{
	struct ir_insn *new_insn = create_alu_nonbin(
		env, bb->ir_bb, read_variable(env, tenv, insn.dst_reg, bb),
		IR_INSN_NEG, alu_ty);
	struct ir_value v = bpf_ir_value_insn(new_insn);
	set_insn_raw_pos(new_insn, insn.pos);
	set_value_raw_pos(&v, insn.pos, IR_RAW_POS_INSN);
	set_value_raw_pos(&new_insn->values[0], insn.pos, IR_RAW_POS_DST);
	write_variable(env, tenv, insn.dst_reg, bb, v);
}

static void bpf_end_write(struct bpf_ir_env *env,
			  struct ssa_transform_env *tenv,
			  struct pre_ir_insn insn,
			  struct pre_ir_basic_block *bb, enum ir_insn_type ty)
{
	struct ir_insn *new_insn = create_alu_nonbin(
		env, bb->ir_bb, read_variable(env, tenv, insn.dst_reg, bb), ty,
		IR_ALU_32);
	new_insn->swap_width = insn.imm;
	struct ir_value v = bpf_ir_value_insn(new_insn);
	set_insn_raw_pos(new_insn, insn.pos);
	set_value_raw_pos(&v, insn.pos, IR_RAW_POS_INSN);
	set_value_raw_pos(&new_insn->values[0], insn.pos, IR_RAW_POS_DST);
	write_variable(env, tenv, insn.dst_reg, bb, v);
}

static void create_cond_jmp(struct bpf_ir_env *env,
			    struct ssa_transform_env *tenv,
			    struct pre_ir_basic_block *bb,
			    struct pre_ir_insn insn, enum ir_insn_type ty,
			    enum ir_alu_op_type alu_ty)
{
	struct ir_insn *new_insn = create_insn_back(bb->ir_bb);
	new_insn->op = ty;
	new_insn->values[0] = read_variable(env, tenv, insn.dst_reg, bb);
	new_insn->values[1] = get_src_value(env, tenv, bb, insn);
	new_insn->value_num = 2;
	new_insn->alu_op = alu_ty;
	add_user(env, new_insn, new_insn->values[0]);
	add_user(env, new_insn, new_insn->values[1]);
	size_t pos = insn.pos + insn.off + 1;
	new_insn->bb1 = get_ir_bb_from_position(tenv, insn.pos + 1);
	new_insn->bb2 = get_ir_bb_from_position(tenv, pos);
	bpf_ir_array_push(env, &new_insn->bb1->users, &new_insn);
	bpf_ir_array_push(env, &new_insn->bb2->users, &new_insn);

	set_insn_raw_pos(new_insn, insn.pos);
	set_value_raw_pos(&new_insn->values[0], insn.pos, IR_RAW_POS_DST);
}

static void transform_bb(struct bpf_ir_env *env, struct ssa_transform_env *tenv,
			 struct pre_ir_basic_block *bb)
{
	// PRINT_LOG_DEBUG(env, "Transforming BB%zu\n", bb->id);
	if (bb->sealed) {
		return;
	}
	// Try sealing a BB
	u8 pred_all_filled = 1;
	for (size_t i = 0; i < bb->preds.num_elem; ++i) {
		struct pre_ir_basic_block *pred =
			((struct pre_ir_basic_block **)(bb->preds.data))[i];
		if (!pred->filled) {
			// Not filled
			pred_all_filled = 0;
			break;
		}
	}
	if (pred_all_filled) {
		seal_block(env, tenv, bb);
	}
	if (bb->filled) {
		// Already visited (filled)
		return;
	}
	// Fill the BB
	for (size_t i = 0; i < bb->len; ++i) {
		struct pre_ir_insn insn = bb->pre_insns[i];
		u8 code = insn.opcode;
		if (BPF_CLASS(code) == BPF_ALU ||
		    BPF_CLASS(code) == BPF_ALU64) {
			// ALU class
			enum ir_alu_op_type alu_ty = IR_ALU_UNKNOWN;
			if (BPF_CLASS(code) == BPF_ALU) {
				alu_ty = IR_ALU_32;
			} else {
				alu_ty = IR_ALU_64;
			}
			if (BPF_OP(code) == BPF_ADD) {
				alu_write_bin(env, tenv, IR_INSN_ADD, insn, bb,
					      alu_ty);
			} else if (BPF_OP(code) == BPF_SUB) {
				alu_write_bin(env, tenv, IR_INSN_SUB, insn, bb,
					      alu_ty);
			} else if (BPF_OP(code) == BPF_MUL) {
				alu_write_bin(env, tenv, IR_INSN_MUL, insn, bb,
					      alu_ty);
			} else if (BPF_OP(code) == BPF_DIV) {
				alu_write_bin(env, tenv, IR_INSN_DIV, insn, bb,
					      alu_ty);
			} else if (BPF_OP(code) == BPF_OR) {
				alu_write_bin(env, tenv, IR_INSN_OR, insn, bb,
					      alu_ty);
			} else if (BPF_OP(code) == BPF_AND) {
				alu_write_bin(env, tenv, IR_INSN_AND, insn, bb,
					      alu_ty);
			} else if (BPF_OP(code) == BPF_MOV) {
				// Do not create instructions
				struct ir_value v =
					get_src_value(env, tenv, bb, insn);
				if (BPF_SRC(code) == BPF_K) {
					// Mov a constant
					// mov64 xx
					// mov xx
					v.const_type = IR_ALU_32;
				}
				write_variable(env, tenv, insn.dst_reg, bb, v);
			} else if (BPF_OP(code) == BPF_LSH) {
				alu_write_bin(env, tenv, IR_INSN_LSH, insn, bb,
					      alu_ty);
			} else if (BPF_OP(code) == BPF_ARSH) {
				alu_write_bin(env, tenv, IR_INSN_ARSH, insn, bb,
					      alu_ty);
			} else if (BPF_OP(code) == BPF_RSH) {
				alu_write_bin(env, tenv, IR_INSN_RSH, insn, bb,
					      alu_ty);
			} else if (BPF_OP(code) == BPF_MOD) {
				// dst = (src != 0) ? (dst % src) : dst
				alu_write_bin(env, tenv, IR_INSN_MOD, insn, bb,
					      alu_ty);
			} else if (BPF_OP(code) == BPF_XOR) {
				// dst = dst ^ src
				alu_write_bin(env, tenv, IR_INSN_XOR, insn, bb,
					      alu_ty);
			} else if (BPF_OP(code) ==
				   BPF_END) { /* Non-binary ALU operations */
				if (alu_ty == IR_ALU_64) {
					// Wrong instruction
					RAISE_ERROR(
						"BPF_END is not supported in 64-bit mode");
				}
				if (BPF_SRC(code) == BPF_TO_BE) {
					bpf_end_write(env, tenv, insn, bb,
						      IR_INSN_HTOBE);
				} else if (BPF_SRC(code) == BPF_TO_LE) {
					bpf_end_write(env, tenv, insn, bb,
						      IR_INSN_HTOLE);
				} else {
					RAISE_ERROR(
						"Unknown BPF_END instruction");
				}
			} else if (BPF_OP(code) == BPF_NEG) {
				// dst = -dst
				if (BPF_SRC(insn.opcode) != BPF_K) {
					RAISE_ERROR("Neg with src != BPF_K");
				}
				bpf_neg_write(env, tenv, insn, bb, alu_ty);
			} else {
				// TODO
				PRINT_LOG_ERROR(
					env, "Unknown opcode: %d at insn %d\n",
					code, insn.pos);
				RAISE_ERROR(
					"Unknown ALU instruction, not supported");
			}
			if (insn.off != 0) {
				RAISE_ERROR("Offset not 0, invalid program");
			}

		} else if (BPF_CLASS(code) == BPF_LD &&
			   BPF_MODE(code) == BPF_IMM &&
			   BPF_SIZE(code) == BPF_DW) {
			// 64-bit immediate load
			if (insn.src_reg >= 0 && insn.src_reg <= 0x06) {
				// BPF MAP instructions
				struct ir_insn *new_insn =
					create_insn_back(bb->ir_bb);

				new_insn->op = IR_INSN_LOADIMM_EXTRA;
				new_insn->imm_extra_type = insn.src_reg;
				new_insn->imm64 = insn.imm64;
				set_insn_raw_pos(new_insn, insn.pos);
				write_variable(env, tenv, insn.dst_reg, bb,
					       bpf_ir_value_insn(new_insn));
			} else {
				RAISE_ERROR("Not supported");
			}
		} else if (BPF_CLASS(code) == BPF_LDX &&
			   BPF_MODE(code) == BPF_MEMSX) {
			// dst = *(signed size *) (src + offset)
			// https://www.kernel.org/doc/html/v6.6/bpf/standardization/instruction-set.html#sign-extension-load-operations

			struct ir_insn *new_insn = create_insn_back(bb->ir_bb);
			new_insn->op = IR_INSN_LOADRAW;
			struct ir_address_value addr_val;
			addr_val.value =
				read_variable(env, tenv, insn.src_reg, bb);
			add_user(env, new_insn, addr_val.value);
			set_value_raw_pos(&addr_val.value, insn.pos,
					  IR_RAW_POS_SRC);
			addr_val.offset = insn.off;
			if (insn.src_reg == BPF_REG_10) {
				addr_val.offset_type = IR_VALUE_CONSTANT_RAWOFF;
			} else {
				addr_val.offset_type = IR_VALUE_CONSTANT;
			}
			new_insn->vr_type = to_ir_ld_u(BPF_SIZE(code));
			new_insn->addr_val = addr_val;

			set_insn_raw_pos(new_insn, insn.pos);
			write_variable(env, tenv, insn.dst_reg, bb,
				       bpf_ir_value_insn(new_insn));
		} else if (BPF_CLASS(code) == BPF_LDX &&
			   BPF_MODE(code) == BPF_MEM) {
			// Regular load
			// dst = *(unsigned size *) (src + offset)
			// https://www.kernel.org/doc/html/v6.6/bpf/standardization/instruction-set.html#regular-load-and-store-operations
			// TODO: use LOAD instead of LOADRAW
			struct ir_insn *new_insn = create_insn_back(bb->ir_bb);
			new_insn->op = IR_INSN_LOADRAW;
			struct ir_address_value addr_val;
			if (insn.src_reg == BPF_REG_10) {
				addr_val.offset_type = IR_VALUE_CONSTANT_RAWOFF;
			} else {
				addr_val.offset_type = IR_VALUE_CONSTANT;
			}
			addr_val.value =
				read_variable(env, tenv, insn.src_reg, bb);
			set_value_raw_pos(&addr_val.value, insn.pos,
					  IR_RAW_POS_SRC);
			add_user(env, new_insn, addr_val.value);
			addr_val.offset = insn.off;
			new_insn->vr_type = to_ir_ld_u(BPF_SIZE(code));
			new_insn->addr_val = addr_val;

			set_insn_raw_pos(new_insn, insn.pos);
			write_variable(env, tenv, insn.dst_reg, bb,
				       bpf_ir_value_insn(new_insn));
		} else if (BPF_CLASS(code) == BPF_ST &&
			   BPF_MODE(code) == BPF_MEM) {
			// *(size *) (dst + offset) = imm32
			struct ir_insn *new_insn = create_insn_back(bb->ir_bb);
			new_insn->op = IR_INSN_STORERAW;
			struct ir_address_value addr_val;
			if (insn.dst_reg == BPF_REG_10) {
				addr_val.offset_type = IR_VALUE_CONSTANT_RAWOFF;
			} else {
				addr_val.offset_type = IR_VALUE_CONSTANT;
			}
			addr_val.value =
				read_variable(env, tenv, insn.dst_reg, bb);
			set_value_raw_pos(&addr_val.value, insn.pos,
					  IR_RAW_POS_DST);
			add_user(env, new_insn, addr_val.value);
			addr_val.offset = insn.off;
			new_insn->vr_type = to_ir_ld_u(BPF_SIZE(code));
			new_insn->addr_val = addr_val;
			new_insn->values[0] = bpf_ir_value_const32(insn.imm);
			new_insn->value_num = 1;
			set_value_raw_pos(&new_insn->values[0], insn.pos,
					  IR_RAW_POS_IMM);
			set_insn_raw_pos(new_insn, insn.pos);
		} else if (BPF_CLASS(code) == BPF_STX &&
			   BPF_MODE(code) == BPF_MEM) {
			// *(size *) (dst + offset) = src
			struct ir_insn *new_insn = create_insn_back(bb->ir_bb);
			new_insn->op = IR_INSN_STORERAW;
			struct ir_address_value addr_val;
			if (insn.dst_reg == BPF_REG_10) {
				addr_val.offset_type = IR_VALUE_CONSTANT_RAWOFF;
			} else {
				addr_val.offset_type = IR_VALUE_CONSTANT;
			}
			addr_val.value =
				read_variable(env, tenv, insn.dst_reg, bb);
			set_value_raw_pos(&addr_val.value, insn.pos,
					  IR_RAW_POS_DST);
			add_user(env, new_insn, addr_val.value);
			addr_val.offset = insn.off;
			new_insn->vr_type = to_ir_ld_u(BPF_SIZE(code));
			new_insn->addr_val = addr_val;
			new_insn->values[0] =
				read_variable(env, tenv, insn.src_reg, bb);
			set_value_raw_pos(&new_insn->values[0], insn.pos,
					  IR_RAW_POS_SRC);
			new_insn->value_num = 1;
			add_user(env, new_insn, new_insn->values[0]);
			set_insn_raw_pos(new_insn, insn.pos);
		} else if (BPF_CLASS(code) == BPF_JMP ||
			   BPF_CLASS(code) == BPF_JMP32) {
			enum ir_alu_op_type alu_ty = IR_ALU_UNKNOWN;
			if (BPF_CLASS(code) == BPF_JMP) {
				alu_ty = IR_ALU_64;
			} else {
				alu_ty = IR_ALU_32;
			}
			if (BPF_OP(code) == BPF_JA) {
				// Direct Jump
				// PC += offset
				struct ir_insn *new_insn =
					create_insn_back(bb->ir_bb);
				new_insn->op = IR_INSN_JA;
				size_t pos = insn.pos + insn.off + 1;
				new_insn->bb1 =
					get_ir_bb_from_position(tenv, pos);
				set_insn_raw_pos(new_insn, insn.pos);
				bpf_ir_array_push(env, &new_insn->bb1->users,
						  &new_insn);
			} else if (BPF_OP(code) == BPF_EXIT) {
				// Exit
				struct ir_insn *new_insn =
					create_insn_back(bb->ir_bb);
				new_insn->op = IR_INSN_RET;
				new_insn->values[0] =
					read_variable(env, tenv, BPF_REG_0, bb);
				new_insn->value_num = 1;
				add_user(env, new_insn, new_insn->values[0]);
				set_insn_raw_pos(new_insn, insn.pos);
			} else if (BPF_OP(code) == BPF_JEQ) {
				// PC += offset if dst == src
				create_cond_jmp(env, tenv, bb, insn,
						IR_INSN_JEQ, alu_ty);
			} else if (BPF_OP(code) == BPF_JLT) {
				// PC += offset if dst < src
				create_cond_jmp(env, tenv, bb, insn,
						IR_INSN_JLT, alu_ty);
			} else if (BPF_OP(code) == BPF_JLE) {
				// PC += offset if dst <= src
				create_cond_jmp(env, tenv, bb, insn,
						IR_INSN_JLE, alu_ty);
			} else if (BPF_OP(code) == BPF_JGT) {
				// PC += offset if dst > src
				create_cond_jmp(env, tenv, bb, insn,
						IR_INSN_JGT, alu_ty);
			} else if (BPF_OP(code) == BPF_JGE) {
				// PC += offset if dst >= src
				create_cond_jmp(env, tenv, bb, insn,
						IR_INSN_JGE, alu_ty);
			} else if (BPF_OP(code) == BPF_JNE) {
				// PC += offset if dst != src
				create_cond_jmp(env, tenv, bb, insn,
						IR_INSN_JNE, alu_ty);
			} else if (BPF_OP(code) == BPF_JSGT) {
				// PC += offset if dst s> src
				create_cond_jmp(env, tenv, bb, insn,
						IR_INSN_JSGT, alu_ty);
			} else if (BPF_OP(code) == BPF_JSLT) {
				// PC += offset if dst s< src
				create_cond_jmp(env, tenv, bb, insn,
						IR_INSN_JSLT, alu_ty);
			} else if (BPF_OP(code) == BPF_CALL) {
				// imm is the function id
				struct ir_insn *new_insn =
					create_insn_back(bb->ir_bb);
				set_insn_raw_pos(new_insn, insn.pos);
				new_insn->op = IR_INSN_CALL;
				new_insn->fid = insn.imm;
				if (insn.imm < 0) {
					new_insn->value_num = 0;
					RAISE_ERROR(
						"Not supported function call\n");
				} else {
					// Test if the helper function is supported
					if (insn.imm < 0 ||
					    (size_t)insn.imm >=
						    sizeof(helper_func_arg_num) /
							    sizeof(helper_func_arg_num
									   [0])) {
						PRINT_LOG_ERROR(
							env,
							"unknown helper function %d at %d\n",
							insn.imm, insn.pos);
						RAISE_ERROR(
							"Unsupported helper function");
					}
					if (helper_func_arg_num[insn.imm] < 0) {
						// Variable length, infer from previous instructions
						new_insn->value_num = 0;
						// used[x] means whether there exists a usage of register x + 1
						for (u8 j = 0; j < MAX_FUNC_ARG;
						     ++j) {
							if (is_variable_defined(
								    tenv,
								    j + BPF_REG_1,
								    bb)) {
								new_insn->value_num =
									j +
									BPF_REG_1;
							} else {
								break;
							}
						}
					} else {
						new_insn->value_num =
							helper_func_arg_num
								[insn.imm];
					}
					if (new_insn->value_num >
					    MAX_FUNC_ARG) {
						RAISE_ERROR(
							"Too many arguments");
					}
					for (size_t j = 0;
					     j < new_insn->value_num; ++j) {
						new_insn->values[j] =
							read_variable(
								env, tenv,
								BPF_REG_1 + j,
								bb);
						add_user(env, new_insn,
							 new_insn->values[j]);
					}
				}

				write_variable(env, tenv, BPF_REG_0, bb,
					       bpf_ir_value_insn(new_insn));
			} else {
				// TODO
				PRINT_LOG_ERROR(
					env,
					"unknown jmp instruction %d at %d\n",
					code, insn.pos);
				RAISE_ERROR("Not supported jmp instruction");
			}
		} else {
			// TODO
			PRINT_LOG_ERROR(env, "Class 0x%02x not supported\n",
					BPF_CLASS(code));
			RAISE_ERROR("Not supported");
		}
	}
	bb->filled = 1;
	// Finish filling
	for (size_t i = 0; i < bb->succs.num_elem; ++i) {
		struct pre_ir_basic_block *succ =
			((struct pre_ir_basic_block **)(bb->succs.data))[i];
		transform_bb(env, tenv, succ);
		CHECK_ERR();
	}
}

struct ir_insn *bpf_ir_find_ir_insn_by_rawpos(struct ir_function *fun,
					      size_t rawpos)
{
	// Scan through the IR to check if there is an instruction that maps to pos
	struct ir_basic_block **pos;
	array_for(pos, fun->reachable_bbs)
	{
		struct ir_basic_block *bb = *pos;
		struct ir_insn *insn;
		list_for_each_entry(insn, &bb->ir_insn_head, list_ptr) {
			if (insn->raw_pos.valid) {
				DBGASSERT(insn->raw_pos.pos_t ==
					  IR_RAW_POS_INSN);
				if (insn->raw_pos.pos == rawpos) {
					return insn;
				}
			}
		}
	}
	return NULL;
}

void bpf_ir_free_function(struct ir_function *fun)
{
	for (size_t i = 0; i < fun->all_bbs.num_elem; ++i) {
		struct ir_basic_block *bb =
			((struct ir_basic_block **)(fun->all_bbs.data))[i];

		bpf_ir_array_free(&bb->preds);
		bpf_ir_array_free(&bb->succs);
		bpf_ir_array_free(&bb->users);
		// Free the instructions
		struct ir_insn *pos = NULL, *n = NULL;
		list_for_each_entry_safe(pos, n, &bb->ir_insn_head, list_ptr) {
			list_del(&pos->list_ptr);
			bpf_ir_array_free(&pos->users);
			if (pos->op == IR_INSN_PHI) {
				bpf_ir_array_free(&pos->phi);
			}
			free_proto(pos);
		}
		free_proto(bb);
	}
	for (u8 i = 0; i < MAX_FUNC_ARG; ++i) {
		bpf_ir_array_free(&fun->function_arg[i]->users);
		free_proto(fun->function_arg[i]);
	}
	if (fun->sp) {
		bpf_ir_array_free(&fun->sp->users);
		free_proto(fun->sp);
	}
	for (u8 i = 0; i < BPF_REG_10; ++i) {
		struct ir_insn *insn = fun->cg_info.regs[i];
		bpf_ir_array_free(&insn->users);
		free_proto(insn);
	}
	bpf_ir_array_free(&fun->all_bbs);
	bpf_ir_array_free(&fun->reachable_bbs);
	bpf_ir_array_free(&fun->end_bbs);
	bpf_ir_array_free(&fun->cg_info.all_var);
}

static void init_function(struct bpf_ir_env *env, struct ir_function *fun,
			  struct ssa_transform_env *tenv)
{
	fun->arg_num = 1;
	fun->entry = tenv->info.entry->ir_bb;
	fun->sp = tenv->sp;
	for (u8 i = 0; i < MAX_FUNC_ARG; ++i) {
		fun->function_arg[i] = tenv->function_arg[i];
	}
	INIT_ARRAY(&fun->all_bbs, struct ir_basic_block *);
	INIT_ARRAY(&fun->reachable_bbs, struct ir_basic_block *);
	INIT_ARRAY(&fun->end_bbs, struct ir_basic_block *);
	INIT_ARRAY(&fun->cg_info.all_var, struct ir_insn *);
	for (size_t i = 0; i < MAX_BPF_REG; ++i) {
		struct array *currentDef = &tenv->currentDef[i];
		bpf_ir_array_free(currentDef);
	}
	for (size_t i = 0; i < tenv->info.all_bbs.num_elem; ++i) {
		struct pre_ir_basic_block *bb = ((
			struct bb_entrance_info *)(tenv->info.all_bbs.data))[i]
							.bb;
		bpf_ir_array_free(&bb->preds);
		bpf_ir_array_free(&bb->succs);
		free_proto(bb->pre_insns);
		bb->ir_bb->user_data = NULL;
		bpf_ir_array_push(env, &fun->all_bbs, &bb->ir_bb);
		free_proto(bb);
	}
	for (u8 i = 0; i < BPF_REG_10; ++i) {
		struct ir_insn *insn;
		SAFE_MALLOC(fun->cg_info.regs[i], sizeof(struct ir_insn));
		// Those should be read-only
		insn = fun->cg_info.regs[i];
		insn->op = IR_INSN_REG;
		insn->parent_bb = NULL;
		INIT_ARRAY(&insn->users, struct ir_insn *);
		insn->value_num = 0;
		insn->reg_id = i;
	}
}

static void gen_bb_succ(struct bpf_ir_env *env, struct ir_function *fun)
{
	struct ir_basic_block **pos;
	array_for(pos, fun->all_bbs)
	{
		struct ir_basic_block *bb = *pos;
		struct ir_insn *insn = bpf_ir_get_last_insn(bb);
		if (!insn) {
			// Empty BB
			continue;
		}
		if (bpf_ir_is_cond_jmp(insn)) {
			// Conditional jmp
			if (bb->succs.num_elem != 2) {
				print_ir_insn_err(env, insn,
						  "Jump instruction");
				RAISE_ERROR(
					"Conditional jmp with != 2 successors");
			}
			struct ir_basic_block **s1 = array_get(
				&bb->succs, 0, struct ir_basic_block *);
			struct ir_basic_block **s2 = array_get(
				&bb->succs, 1, struct ir_basic_block *);
			*s1 = insn->bb1;
			*s2 = insn->bb2;
		}
		if (insn->op == IR_INSN_JA) {
			if (bb->succs.num_elem != 1) {
				print_ir_insn_err(env, insn,
						  "Jump instruction");
				RAISE_ERROR("JA jmp with != 1 successors");
			}
			struct ir_basic_block **s1 = array_get(
				&bb->succs, 0, struct ir_basic_block *);
			*s1 = insn->bb1;
		}
	}
}

static void add_reach(struct bpf_ir_env *env, struct ir_function *fun,
		      struct ir_basic_block *bb)
{
	if (bb->_visited) {
		return;
	}
	// bb->_visited = 1;
	// bpf_ir_array_push(env, &fun->reachable_bbs, &bb);
	struct array todo;
	INIT_ARRAY(&todo, struct ir_basic_block *);

	// struct ir_basic_block **succ;
	// bool first = false;
	// array_for(succ, bb->succs)
	// {
	// 	if (!first && bb->succs.num_elem > 1) {
	// 		first = true;
	// 		// Check if visited
	// 		if ((*succ)->_visited) {
	// 			RAISE_ERROR("Loop BB detected");
	// 		}
	// 	}
	// 	add_reach(env, fun, *succ);
	// }

	// First Test sanity ... TODO!

	struct ir_basic_block *cur_bb = bb;

	while (1) {
		cur_bb->_visited = 1;
		bpf_ir_array_push(env, &fun->reachable_bbs, &cur_bb);
		if (cur_bb->succs.num_elem == 0) {
			break;
		}

		struct ir_basic_block **succ1 =
			bpf_ir_array_get_void(&cur_bb->succs, 0);
		if ((*succ1)->_visited) {
			break;
		}
		if (cur_bb->succs.num_elem == 1) {
		} else if (cur_bb->succs.num_elem == 2) {
			struct ir_basic_block **succ2 =
				bpf_ir_array_get_void(&cur_bb->succs, 1);
			bpf_ir_array_push(env, &todo, succ2);
		} else {
			CRITICAL("Not possible: BB with >2 succs");
		}
		cur_bb = *succ1;
	}

	struct ir_basic_block **pos;
	array_for(pos, todo)
	{
		add_reach(env, fun, *pos);
	}

	bpf_ir_array_free(&todo);
}

static void gen_reachable_bbs(struct bpf_ir_env *env, struct ir_function *fun)
{
	bpf_ir_clean_visited(fun);
	bpf_ir_array_clear(env, &fun->reachable_bbs);
	add_reach(env, fun, fun->entry);
}

static void gen_end_bbs(struct bpf_ir_env *env, struct ir_function *fun)
{
	struct ir_basic_block **pos;
	bpf_ir_array_clear(env, &fun->end_bbs);
	array_for(pos, fun->reachable_bbs)
	{
		struct ir_basic_block *bb = *pos;
		if (bb->succs.num_elem == 0) {
			bpf_ir_array_push(env, &fun->end_bbs, &bb);
		}
	}
}

static void bpf_ir_pass_postprocess(struct bpf_ir_env *env,
				    struct ir_function *fun)
{
	gen_bb_succ(env, fun);
	CHECK_ERR();
	bpf_ir_clean_metadata_all(fun);
	gen_reachable_bbs(env, fun);
	CHECK_ERR();
	gen_end_bbs(env, fun);
	CHECK_ERR();
	if (!env->opts.disable_prog_check) {
		bpf_ir_prog_check(env, fun);
	}
}

static void run_single_pass(struct bpf_ir_env *env, struct ir_function *fun,
			    const struct function_pass *pass, void *param)
{
	PRINT_LOG_DEBUG(env, "\x1B[32m------ Running Pass: %s ------\x1B[0m\n",
			pass->name);
	pass->pass(env, fun, param);
	CHECK_ERR();

	// Validate the IR
	bpf_ir_pass_postprocess(env, fun);
	CHECK_ERR();

	print_ir_prog(env, fun);
	CHECK_ERR();
}

void bpf_ir_run(struct bpf_ir_env *env, struct ir_function *fun)
{
	u64 starttime = get_cur_time_ns();
	for (size_t i = 0; i < sizeof(pre_passes) / sizeof(pre_passes[0]);
	     ++i) {
		bool has_override = false;
		for (size_t j = 0; j < env->opts.builtin_pass_cfg_num; ++j) {
			if (strcmp(env->opts.builtin_pass_cfg[j].name,
				   pre_passes[i].name) == 0) {
				has_override = true;
				if (pre_passes[i].force_enable ||
				    env->opts.builtin_pass_cfg[j].enable) {
					run_single_pass(
						env, fun, &pre_passes[i],
						env->opts.builtin_pass_cfg[j]
							.param);
				}
				break;
			}
		}
		if (!has_override) {
			if (pre_passes[i].enabled) {
				run_single_pass(env, fun, &pre_passes[i], NULL);
			}
		}

		CHECK_ERR();
	}
	for (size_t i = 0; i < env->opts.custom_pass_num; ++i) {
		if (env->opts.custom_passes[i].pass.enabled) {
			if (env->opts.custom_passes[i].check_apply) {
				if (env->opts.custom_passes[i].check_apply(
					    env->verifier_err)) {
					// Pass
					run_single_pass(
						env, fun,
						&env->opts.custom_passes[i].pass,
						env->opts.custom_passes[i]
							.param);
				}
			} else {
				run_single_pass(
					env, fun,
					&env->opts.custom_passes[i].pass,
					env->opts.custom_passes[i].param);
			}
			CHECK_ERR();
		}
	}
	for (size_t i = 0; i < sizeof(post_passes) / sizeof(post_passes[0]);
	     ++i) {
		bool has_override = false;
		for (size_t j = 0; j < env->opts.builtin_pass_cfg_num; ++j) {
			if (strcmp(env->opts.builtin_pass_cfg[j].name,
				   post_passes[i].name) == 0) {
				has_override = true;
				if (post_passes[i].force_enable ||
				    env->opts.builtin_pass_cfg[j].enable) {
					run_single_pass(
						env, fun, &post_passes[i],
						env->opts.builtin_pass_cfg[j]
							.param);
				}
				break;
			}
		}
		if (!has_override) {
			if (post_passes[i].enabled) {
				run_single_pass(env, fun, &post_passes[i],
						NULL);
			}
		}
		CHECK_ERR();
	}

	env->run_time += get_cur_time_ns() - starttime;
}

static void print_bpf_insn_simple(struct bpf_ir_env *env,
				  const struct bpf_insn *insn)
{
	if (insn->off < 0) {
		PRINT_LOG_DEBUG(env, "%4x       %x       %x %8x -%8x\n",
				insn->code, insn->src_reg, insn->dst_reg,
				insn->imm, -insn->off);
	} else {
		PRINT_LOG_DEBUG(env, "%4x       %x       %x %8x  %8x\n",
				insn->code, insn->src_reg, insn->dst_reg,
				insn->imm, insn->off);
	}
}

static void print_bpf_prog_dump(struct bpf_ir_env *env,
				const struct bpf_insn *insns, size_t len)
{
	for (u32 i = 0; i < len; ++i) {
		const struct bpf_insn *insn = &insns[i];
		__u64 data;
		memcpy(&data, insn, sizeof(struct bpf_insn));
		PRINT_LOG_DEBUG(env, "insn[%d]: %llu\n", i, data);
	}
}

static void print_bpf_prog(struct bpf_ir_env *env, const struct bpf_insn *insns,
			   size_t len)
{
	if (env->opts.print_mode == BPF_IR_PRINT_DUMP) {
		print_bpf_prog_dump(env, insns, len);
		return;
	}
	if (env->opts.print_mode == BPF_IR_PRINT_DETAIL) {
		PRINT_LOG_DEBUG(
			env, "      op     src     dst      imm       off\n");
	} else if (env->opts.print_mode == BPF_IR_PRINT_BPF_DETAIL) {
		PRINT_LOG_DEBUG(env,
				"  op     src     dst      imm       off\n");
	}
	for (size_t i = 0; i < len; ++i) {
		const struct bpf_insn *insn = &insns[i];
		if (insn->code == 0) {
			continue;
		}
		PRINT_LOG_DEBUG(env, "[%zu] ", i);
		if (env->opts.print_mode == BPF_IR_PRINT_BPF ||
		    env->opts.print_mode == BPF_IR_PRINT_BPF_DETAIL) {
			bpf_ir_print_bpf_insn(env, insn);
		}
		if (env->opts.print_mode == BPF_IR_PRINT_DETAIL ||
		    env->opts.print_mode == BPF_IR_PRINT_BPF_DETAIL) {
			print_bpf_insn_simple(env, insn);
		}
	}
}

// Interface implementation

struct ir_function *bpf_ir_lift(struct bpf_ir_env *env,
				const struct bpf_insn *insns, size_t len)
{
	u64 starttime = get_cur_time_ns();
	struct bb_info info;
	gen_bb(env, &info, insns, len);
	CHECK_ERR(NULL);

	if (env->opts.verbose > 2) {
		print_pre_ir_cfg(env, info.entry);
	}
	struct ssa_transform_env trans_env;
	init_tenv(env, &trans_env, info);
	CHECK_ERR(NULL);

	init_ir_bbs(env, &trans_env);
	CHECK_ERR(NULL);

	transform_bb(env, &trans_env, info.entry);
	CHECK_ERR(NULL);

	struct ir_function *fun;
	SAFE_MALLOC_RET_NULL(fun, sizeof(struct ir_function));
	init_function(env, fun, &trans_env);
	bpf_ir_pass_postprocess(env, fun);
	CHECK_ERR(NULL);

	env->lift_time += get_cur_time_ns() - starttime;

	return fun;
}

void bpf_ir_autorun(struct bpf_ir_env *env)
{
	env->executed = true;
	const struct bpf_insn *insns = env->insns;
	size_t len = env->insn_cnt;
	struct ir_function *fun = bpf_ir_lift(env, insns, len);
	CHECK_ERR();

	print_ir_prog(env, fun);
	PRINT_LOG_DEBUG(env, "Starting IR Passes...\n");
	// Start IR manipulation

	bpf_ir_run(env, fun);
	CHECK_ERR();

	// End IR manipulation
	PRINT_LOG_DEBUG(env, "IR Passes Ended!\n");

	bpf_ir_compile(env, fun);
	CHECK_ERR();

	// Got the bpf bytecode

	PRINT_LOG_DEBUG(env,
			"--------------------\nOriginal Program, size %zu:\n",
			len);
	print_bpf_prog(env, insns, len);
	PRINT_LOG_DEBUG(env,
			"--------------------\nRewritten Program, size %zu:\n",
			env->insn_cnt);
	print_bpf_prog(env, env->insns, env->insn_cnt);

	// Free the memory
	bpf_ir_free_function(fun);
}

struct bpf_ir_opts bpf_ir_default_opts(void)
{
	struct bpf_ir_opts opts;
	opts.print_mode = BPF_IR_PRINT_BPF;
	opts.builtin_pass_cfg_num = 0;
	opts.custom_pass_num = 0;
	opts.enable_coalesce = false;
	opts.force = false;
	opts.verbose = 1;
	opts.max_iteration = 10;
	opts.disable_prog_check = false;
	opts.enable_throw_msg = false;
	return opts;
}

struct bpf_ir_env *bpf_ir_init_env(struct bpf_ir_opts opts,
				   const struct bpf_insn *insns, size_t len)
{
	struct bpf_ir_env *env = malloc_proto(sizeof(struct bpf_ir_env));
	env->insn_cnt = len;
	env->insns = malloc_proto(sizeof(struct bpf_insn) * len);
	memcpy(env->insns, insns, sizeof(struct bpf_insn) * len);
	env->log_pos = 0;
	env->err = 0;
	env->opts = opts;
	env->verifier_err = -1;
	env->executed = false;
	env->venv = NULL;
	env->verifier_log_end_pos = 0;
	env->prog_type = 0; // Unspecified
	env->lift_time = 0;
	env->cg_time = 0;
	env->run_time = 0;

	return env;
}

void bpf_ir_free_env(struct bpf_ir_env *env)
{
	free_proto(env->insns);
	free_proto(env);
}
