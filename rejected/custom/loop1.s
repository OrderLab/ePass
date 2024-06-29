
loop1.o:	file format elf64-bpf

Disassembly of section xdp:

0000000000000000 <prog>:
;     __u64 t = bpf_ktime_get_ns();
       0:	85 00 00 00 05 00 00 00	call 0x5
       1:	bf 06 00 00 00 00 00 00	r6 = r0
;     for (int i = 0; i < t; ++i) {
       2:	15 06 07 00 00 00 00 00	if r6 == 0x0 goto +0x7 <LBB0_3>
       3:	b7 07 00 00 00 00 00 00	r7 = 0x0

0000000000000020 <LBB0_2>:
;         bpf_trace_printk("s", 1);
       4:	18 01 00 00 00 00 00 00 00 00 00 00 00 00 00 00	r1 = 0x0 ll
       6:	b7 02 00 00 01 00 00 00	r2 = 0x1
       7:	85 00 00 00 06 00 00 00	call 0x6
;     for (int i = 0; i < t; ++i) {
       8:	07 07 00 00 01 00 00 00	r7 += 0x1
       9:	2d 76 fa ff 00 00 00 00	if r6 > r7 goto -0x6 <LBB0_2>

0000000000000050 <LBB0_3>:
;     return 0;
      10:	b7 00 00 00 00 00 00 00	r0 = 0x0
      11:	95 00 00 00 00 00 00 00	exit
