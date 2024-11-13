output/progs_ringbuf.o: ./progs/ringbuf.c
	clang -O2 -I./progs -I/usr/include/x86_64-linux-gnu -D__TARGET_ARCH_x86 -target bpf -g -c $< -o $@
output/progs_ringbuf.ll: ./progs/ringbuf.c
	clang -O2 -I./progs -I/usr/include/x86_64-linux-gnu -D__TARGET_ARCH_x86 -target bpf -g -emit-llvm -S -c $< -o $@
output/progs_mem2.o: ./progs/mem2.c
	clang -O2 -I./progs -I/usr/include/x86_64-linux-gnu -D__TARGET_ARCH_x86 -target bpf -g -c $< -o $@
output/progs_mem2.ll: ./progs/mem2.c
	clang -O2 -I./progs -I/usr/include/x86_64-linux-gnu -D__TARGET_ARCH_x86 -target bpf -g -emit-llvm -S -c $< -o $@
output/progs_mem1.o: ./progs/mem1.c
	clang -O2 -I./progs -I/usr/include/x86_64-linux-gnu -D__TARGET_ARCH_x86 -target bpf -g -c $< -o $@
output/progs_mem1.ll: ./progs/mem1.c
	clang -O2 -I./progs -I/usr/include/x86_64-linux-gnu -D__TARGET_ARCH_x86 -target bpf -g -emit-llvm -S -c $< -o $@
output/progs_test_asm.o: ./progs/test_asm.c
	clang -O2 -I./progs -I/usr/include/x86_64-linux-gnu -D__TARGET_ARCH_x86 -target bpf -g -c $< -o $@
output/progs_test_asm.ll: ./progs/test_asm.c
	clang -O2 -I./progs -I/usr/include/x86_64-linux-gnu -D__TARGET_ARCH_x86 -target bpf -g -emit-llvm -S -c $< -o $@
output/progs_loop2.o: ./progs/loop2.c
	clang -O2 -I./progs -I/usr/include/x86_64-linux-gnu -D__TARGET_ARCH_x86 -target bpf -g -c $< -o $@
output/progs_loop2.ll: ./progs/loop2.c
	clang -O2 -I./progs -I/usr/include/x86_64-linux-gnu -D__TARGET_ARCH_x86 -target bpf -g -emit-llvm -S -c $< -o $@
output/progs_loop3.o: ./progs/loop3.c
	clang -O2 -I./progs -I/usr/include/x86_64-linux-gnu -D__TARGET_ARCH_x86 -target bpf -g -c $< -o $@
output/progs_loop3.ll: ./progs/loop3.c
	clang -O2 -I./progs -I/usr/include/x86_64-linux-gnu -D__TARGET_ARCH_x86 -target bpf -g -emit-llvm -S -c $< -o $@
output/progs_simple1.o: ./progs/simple1.c
	clang -O2 -I./progs -I/usr/include/x86_64-linux-gnu -D__TARGET_ARCH_x86 -target bpf -g -c $< -o $@
output/progs_simple1.ll: ./progs/simple1.c
	clang -O2 -I./progs -I/usr/include/x86_64-linux-gnu -D__TARGET_ARCH_x86 -target bpf -g -emit-llvm -S -c $< -o $@
output/progs_libbpf_profile.bpf.o: ./progs/libbpf/profile.bpf.c
	clang -O2 -I./progs -I/usr/include/x86_64-linux-gnu -D__TARGET_ARCH_x86 -target bpf -g -c $< -o $@
output/progs_libbpf_profile.bpf.ll: ./progs/libbpf/profile.bpf.c
	clang -O2 -I./progs -I/usr/include/x86_64-linux-gnu -D__TARGET_ARCH_x86 -target bpf -g -emit-llvm -S -c $< -o $@
output/progs_libbpf_fentry.bpf.o: ./progs/libbpf/fentry.bpf.c
	clang -O2 -I./progs -I/usr/include/x86_64-linux-gnu -D__TARGET_ARCH_x86 -target bpf -g -c $< -o $@
output/progs_libbpf_fentry.bpf.ll: ./progs/libbpf/fentry.bpf.c
	clang -O2 -I./progs -I/usr/include/x86_64-linux-gnu -D__TARGET_ARCH_x86 -target bpf -g -emit-llvm -S -c $< -o $@
output/progs_libbpf_minimal_ns.bpf.o: ./progs/libbpf/minimal_ns.bpf.c
	clang -O2 -I./progs -I/usr/include/x86_64-linux-gnu -D__TARGET_ARCH_x86 -target bpf -g -c $< -o $@
output/progs_libbpf_minimal_ns.bpf.ll: ./progs/libbpf/minimal_ns.bpf.c
	clang -O2 -I./progs -I/usr/include/x86_64-linux-gnu -D__TARGET_ARCH_x86 -target bpf -g -emit-llvm -S -c $< -o $@
output/progs_libbpf_ksyscall.bpf.o: ./progs/libbpf/ksyscall.bpf.c
	clang -O2 -I./progs -I/usr/include/x86_64-linux-gnu -D__TARGET_ARCH_x86 -target bpf -g -c $< -o $@
output/progs_libbpf_ksyscall.bpf.ll: ./progs/libbpf/ksyscall.bpf.c
	clang -O2 -I./progs -I/usr/include/x86_64-linux-gnu -D__TARGET_ARCH_x86 -target bpf -g -emit-llvm -S -c $< -o $@
output/progs_libbpf_task_iter.bpf.o: ./progs/libbpf/task_iter.bpf.c
	clang -O2 -I./progs -I/usr/include/x86_64-linux-gnu -D__TARGET_ARCH_x86 -target bpf -g -c $< -o $@
output/progs_libbpf_task_iter.bpf.ll: ./progs/libbpf/task_iter.bpf.c
	clang -O2 -I./progs -I/usr/include/x86_64-linux-gnu -D__TARGET_ARCH_x86 -target bpf -g -emit-llvm -S -c $< -o $@
output/progs_libbpf_kprobe.bpf.o: ./progs/libbpf/kprobe.bpf.c
	clang -O2 -I./progs -I/usr/include/x86_64-linux-gnu -D__TARGET_ARCH_x86 -target bpf -g -c $< -o $@
output/progs_libbpf_kprobe.bpf.ll: ./progs/libbpf/kprobe.bpf.c
	clang -O2 -I./progs -I/usr/include/x86_64-linux-gnu -D__TARGET_ARCH_x86 -target bpf -g -emit-llvm -S -c $< -o $@
output/progs_libbpf_sockfilter.bpf.o: ./progs/libbpf/sockfilter.bpf.c
	clang -O2 -I./progs -I/usr/include/x86_64-linux-gnu -D__TARGET_ARCH_x86 -target bpf -g -c $< -o $@
output/progs_libbpf_sockfilter.bpf.ll: ./progs/libbpf/sockfilter.bpf.c
	clang -O2 -I./progs -I/usr/include/x86_64-linux-gnu -D__TARGET_ARCH_x86 -target bpf -g -emit-llvm -S -c $< -o $@
output/progs_libbpf_bootstrap.bpf.o: ./progs/libbpf/bootstrap.bpf.c
	clang -O2 -I./progs -I/usr/include/x86_64-linux-gnu -D__TARGET_ARCH_x86 -target bpf -g -c $< -o $@
output/progs_libbpf_bootstrap.bpf.ll: ./progs/libbpf/bootstrap.bpf.c
	clang -O2 -I./progs -I/usr/include/x86_64-linux-gnu -D__TARGET_ARCH_x86 -target bpf -g -emit-llvm -S -c $< -o $@
output/progs_libbpf_minimal_legacy.bpf.o: ./progs/libbpf/minimal_legacy.bpf.c
	clang -O2 -I./progs -I/usr/include/x86_64-linux-gnu -D__TARGET_ARCH_x86 -target bpf -g -c $< -o $@
output/progs_libbpf_minimal_legacy.bpf.ll: ./progs/libbpf/minimal_legacy.bpf.c
	clang -O2 -I./progs -I/usr/include/x86_64-linux-gnu -D__TARGET_ARCH_x86 -target bpf -g -emit-llvm -S -c $< -o $@
output/progs_libbpf_minimal.bpf.o: ./progs/libbpf/minimal.bpf.c
	clang -O2 -I./progs -I/usr/include/x86_64-linux-gnu -D__TARGET_ARCH_x86 -target bpf -g -c $< -o $@
output/progs_libbpf_minimal.bpf.ll: ./progs/libbpf/minimal.bpf.c
	clang -O2 -I./progs -I/usr/include/x86_64-linux-gnu -D__TARGET_ARCH_x86 -target bpf -g -emit-llvm -S -c $< -o $@
output/progs_libbpf_uprobe.bpf.o: ./progs/libbpf/uprobe.bpf.c
	clang -O2 -I./progs -I/usr/include/x86_64-linux-gnu -D__TARGET_ARCH_x86 -target bpf -g -c $< -o $@
output/progs_libbpf_uprobe.bpf.ll: ./progs/libbpf/uprobe.bpf.c
	clang -O2 -I./progs -I/usr/include/x86_64-linux-gnu -D__TARGET_ARCH_x86 -target bpf -g -emit-llvm -S -c $< -o $@
output/progs_libbpf_lsm.bpf.o: ./progs/libbpf/lsm.bpf.c
	clang -O2 -I./progs -I/usr/include/x86_64-linux-gnu -D__TARGET_ARCH_x86 -target bpf -g -c $< -o $@
output/progs_libbpf_lsm.bpf.ll: ./progs/libbpf/lsm.bpf.c
	clang -O2 -I./progs -I/usr/include/x86_64-linux-gnu -D__TARGET_ARCH_x86 -target bpf -g -emit-llvm -S -c $< -o $@
output/progs_alu64.o: ./progs/alu64.c
	clang -O2 -I./progs -I/usr/include/x86_64-linux-gnu -D__TARGET_ARCH_x86 -target bpf -g -c $< -o $@
output/progs_alu64.ll: ./progs/alu64.c
	clang -O2 -I./progs -I/usr/include/x86_64-linux-gnu -D__TARGET_ARCH_x86 -target bpf -g -emit-llvm -S -c $< -o $@
output/progs_str.o: ./progs/str.c
	clang -O2 -I./progs -I/usr/include/x86_64-linux-gnu -D__TARGET_ARCH_x86 -target bpf -g -c $< -o $@
output/progs_str.ll: ./progs/str.c
	clang -O2 -I./progs -I/usr/include/x86_64-linux-gnu -D__TARGET_ARCH_x86 -target bpf -g -emit-llvm -S -c $< -o $@
output/progs_empty.o: ./progs/empty.c
	clang -O2 -I./progs -I/usr/include/x86_64-linux-gnu -D__TARGET_ARCH_x86 -target bpf -g -c $< -o $@
output/progs_empty.ll: ./progs/empty.c
	clang -O2 -I./progs -I/usr/include/x86_64-linux-gnu -D__TARGET_ARCH_x86 -target bpf -g -emit-llvm -S -c $< -o $@
output/progs_map1.o: ./progs/map1.c
	clang -O2 -I./progs -I/usr/include/x86_64-linux-gnu -D__TARGET_ARCH_x86 -target bpf -g -c $< -o $@
output/progs_map1.ll: ./progs/map1.c
	clang -O2 -I./progs -I/usr/include/x86_64-linux-gnu -D__TARGET_ARCH_x86 -target bpf -g -emit-llvm -S -c $< -o $@
output/progs_simple2.o: ./progs/simple2.c
	clang -O2 -I./progs -I/usr/include/x86_64-linux-gnu -D__TARGET_ARCH_x86 -target bpf -g -c $< -o $@
output/progs_simple2.ll: ./progs/simple2.c
	clang -O2 -I./progs -I/usr/include/x86_64-linux-gnu -D__TARGET_ARCH_x86 -target bpf -g -emit-llvm -S -c $< -o $@
output/progs_loop1.o: ./progs/loop1.c
	clang -O2 -I./progs -I/usr/include/x86_64-linux-gnu -D__TARGET_ARCH_x86 -target bpf -g -c $< -o $@
output/progs_loop1.ll: ./progs/loop1.c
	clang -O2 -I./progs -I/usr/include/x86_64-linux-gnu -D__TARGET_ARCH_x86 -target bpf -g -emit-llvm -S -c $< -o $@
output/progs_mask.o: ./progs/mask.c
	clang -O2 -I./progs -I/usr/include/x86_64-linux-gnu -D__TARGET_ARCH_x86 -target bpf -g -c $< -o $@
output/progs_mask.ll: ./progs/mask.c
	clang -O2 -I./progs -I/usr/include/x86_64-linux-gnu -D__TARGET_ARCH_x86 -target bpf -g -emit-llvm -S -c $< -o $@
output/evaluation_compile_speed_speed_20.o: ./evaluation/compile_speed/speed_20.c
	clang -O2 -I./progs -I/usr/include/x86_64-linux-gnu -D__TARGET_ARCH_x86 -target bpf -g -c $< -o $@
output/evaluation_compile_speed_speed_20.ll: ./evaluation/compile_speed/speed_20.c
	clang -O2 -I./progs -I/usr/include/x86_64-linux-gnu -D__TARGET_ARCH_x86 -target bpf -g -emit-llvm -S -c $< -o $@
output/evaluation_compile_speed_speed_100.o: ./evaluation/compile_speed/speed_100.c
	clang -O2 -I./progs -I/usr/include/x86_64-linux-gnu -D__TARGET_ARCH_x86 -target bpf -g -c $< -o $@
output/evaluation_compile_speed_speed_100.ll: ./evaluation/compile_speed/speed_100.c
	clang -O2 -I./progs -I/usr/include/x86_64-linux-gnu -D__TARGET_ARCH_x86 -target bpf -g -emit-llvm -S -c $< -o $@
output/evaluation_compile_speed_speed_50.o: ./evaluation/compile_speed/speed_50.c
	clang -O2 -I./progs -I/usr/include/x86_64-linux-gnu -D__TARGET_ARCH_x86 -target bpf -g -c $< -o $@
output/evaluation_compile_speed_speed_50.ll: ./evaluation/compile_speed/speed_50.c
	clang -O2 -I./progs -I/usr/include/x86_64-linux-gnu -D__TARGET_ARCH_x86 -target bpf -g -emit-llvm -S -c $< -o $@
output/evaluation_counter_loop4.o: ./evaluation/counter/loop4.c
	clang -O2 -I./progs -I/usr/include/x86_64-linux-gnu -D__TARGET_ARCH_x86 -target bpf -g -c $< -o $@
output/evaluation_counter_loop4.ll: ./evaluation/counter/loop4.c
	clang -O2 -I./progs -I/usr/include/x86_64-linux-gnu -D__TARGET_ARCH_x86 -target bpf -g -emit-llvm -S -c $< -o $@
output/evaluation_counter_complex.o: ./evaluation/counter/complex.c
	clang -O2 -I./progs -I/usr/include/x86_64-linux-gnu -D__TARGET_ARCH_x86 -target bpf -g -c $< -o $@
output/evaluation_counter_complex.ll: ./evaluation/counter/complex.c
	clang -O2 -I./progs -I/usr/include/x86_64-linux-gnu -D__TARGET_ARCH_x86 -target bpf -g -emit-llvm -S -c $< -o $@
output/evaluation_counter_loop2.o: ./evaluation/counter/loop2.c
	clang -O2 -I./progs -I/usr/include/x86_64-linux-gnu -D__TARGET_ARCH_x86 -target bpf -g -c $< -o $@
output/evaluation_counter_loop2.ll: ./evaluation/counter/loop2.c
	clang -O2 -I./progs -I/usr/include/x86_64-linux-gnu -D__TARGET_ARCH_x86 -target bpf -g -emit-llvm -S -c $< -o $@
output/evaluation_counter_loop3.o: ./evaluation/counter/loop3.c
	clang -O2 -I./progs -I/usr/include/x86_64-linux-gnu -D__TARGET_ARCH_x86 -target bpf -g -c $< -o $@
output/evaluation_counter_loop3.ll: ./evaluation/counter/loop3.c
	clang -O2 -I./progs -I/usr/include/x86_64-linux-gnu -D__TARGET_ARCH_x86 -target bpf -g -emit-llvm -S -c $< -o $@
output/evaluation_counter_complex2.o: ./evaluation/counter/complex2.c
	clang -O2 -I./progs -I/usr/include/x86_64-linux-gnu -D__TARGET_ARCH_x86 -target bpf -g -c $< -o $@
output/evaluation_counter_complex2.ll: ./evaluation/counter/complex2.c
	clang -O2 -I./progs -I/usr/include/x86_64-linux-gnu -D__TARGET_ARCH_x86 -target bpf -g -emit-llvm -S -c $< -o $@
output/evaluation_counter_loop1.o: ./evaluation/counter/loop1.c
	clang -O2 -I./progs -I/usr/include/x86_64-linux-gnu -D__TARGET_ARCH_x86 -target bpf -g -c $< -o $@
output/evaluation_counter_loop1.ll: ./evaluation/counter/loop1.c
	clang -O2 -I./progs -I/usr/include/x86_64-linux-gnu -D__TARGET_ARCH_x86 -target bpf -g -emit-llvm -S -c $< -o $@
all:output/evaluation_counter_loop1.o output/evaluation_counter_loop1.ll output/evaluation_counter_complex2.o output/evaluation_counter_complex2.ll output/evaluation_counter_loop3.o output/evaluation_counter_loop3.ll output/evaluation_counter_loop2.o output/evaluation_counter_loop2.ll output/evaluation_counter_complex.o output/evaluation_counter_complex.ll output/evaluation_counter_loop4.o output/evaluation_counter_loop4.ll output/evaluation_compile_speed_speed_50.o output/evaluation_compile_speed_speed_50.ll output/evaluation_compile_speed_speed_100.o output/evaluation_compile_speed_speed_100.ll output/evaluation_compile_speed_speed_20.o output/evaluation_compile_speed_speed_20.ll output/progs_mask.o output/progs_mask.ll output/progs_loop1.o output/progs_loop1.ll output/progs_simple2.o output/progs_simple2.ll output/progs_map1.o output/progs_map1.ll output/progs_empty.o output/progs_empty.ll output/progs_str.o output/progs_str.ll output/progs_alu64.o output/progs_alu64.ll output/progs_libbpf_lsm.bpf.o output/progs_libbpf_lsm.bpf.ll output/progs_libbpf_uprobe.bpf.o output/progs_libbpf_uprobe.bpf.ll output/progs_libbpf_minimal.bpf.o output/progs_libbpf_minimal.bpf.ll output/progs_libbpf_minimal_legacy.bpf.o output/progs_libbpf_minimal_legacy.bpf.ll output/progs_libbpf_bootstrap.bpf.o output/progs_libbpf_bootstrap.bpf.ll output/progs_libbpf_sockfilter.bpf.o output/progs_libbpf_sockfilter.bpf.ll output/progs_libbpf_kprobe.bpf.o output/progs_libbpf_kprobe.bpf.ll output/progs_libbpf_task_iter.bpf.o output/progs_libbpf_task_iter.bpf.ll output/progs_libbpf_ksyscall.bpf.o output/progs_libbpf_ksyscall.bpf.ll output/progs_libbpf_minimal_ns.bpf.o output/progs_libbpf_minimal_ns.bpf.ll output/progs_libbpf_fentry.bpf.o output/progs_libbpf_fentry.bpf.ll output/progs_libbpf_profile.bpf.o output/progs_libbpf_profile.bpf.ll output/progs_simple1.o output/progs_simple1.ll output/progs_loop3.o output/progs_loop3.ll output/progs_loop2.o output/progs_loop2.ll output/progs_test_asm.o output/progs_test_asm.ll output/progs_mem1.o output/progs_mem1.ll output/progs_mem2.o output/progs_mem2.ll output/progs_ringbuf.o output/progs_ringbuf.ll 
