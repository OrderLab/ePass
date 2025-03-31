# Evaluation and Testing Suite for ePass

## TO FIX

### OLD

- "output/map_perf_test.bpf.o"
- "output/cpustat_kern.o"
- "output/hbm_out_kern.o"
- "output/test_current_task_under_cgroup.bpf.o"
- "output/progs_tengjiang_access_control.o"
- "output/hbm_edt_kern.o"
- "output/sampleip_kern.o"
- "output/progs_libbpf_task_iter.bpf.o"
- "output/progs_fn_nonrejected_uninit_var_access.o"
- "output/progs_libbpf_fentry.bpf.o"
- "output/sockex3_kern.o"
- "output/progs_libbpf_lsm.bpf.o"

### NEW

- 'output/map_perf_test.bpf.o'

Error: /home/linsy/Projects/ebpf/ePass/core/bpf_ir.c:1478 <gen_bb_succ> Conditional jmp with != 2 successors

- 'output/cpustat_kern.o'

Class 0x03 not supported

- 'output/hbm_out_kern.o'

Class 0x03 not supported

- 'output/evaluation_msan_msan3.o'

double free

- 'output/tcp_rwnd_kern.o'

double free

- 'output/tcp_clamp_kern.o'
- 'output/tcp_iw_kern.o'
- 'output/test_current_task_under_cgroup.bpf.o'
- 'output/tcp_tos_reflect_kern.o'
- 'output/progs_tengjiang_access_control.o'
- 'output/hbm_edt_kern.o'
- 'output/test_probe_write_user.bpf.o'
- 'output/evaluation_masking_map_val_accepted.o'
- 'output/progs_libbpf_task_iter.bpf.o'
- 'output/progs_libbpf_fentry.bpf.o'
- 'output/progs_mem2.o'
- 'output/tcp_basertt_kern.o'
- 'output/sockex3_kern.o'
- 'output/progs_libbpf_lsm.bpf.o'
- 'output/tcp_cong_kern.o'
- 'output/progs_libbpf_ksyscall.bpf.o'
- 'output/tcp_synrto_kern.o'
- 'output/evaluation_masking_map_val_rejected.o'
- 'output/xdp_tx_iptunnel_kern.o'
- 'output/evaluation_msan_msan2.o'