
b2b.o:	file format elf64-bpf

Disassembly of section .text:

0000000000000000 <call1>:
;     bpf_trace_printk("hello", 6);
       0:	18 01 00 00 00 00 00 00 00 00 00 00 00 00 00 00	r1 = 0x0 ll
       2:	b7 02 00 00 06 00 00 00	r2 = 0x6
       3:	85 00 00 00 06 00 00 00	call 0x6
; }
       4:	95 00 00 00 00 00 00 00	exit

0000000000000028 <call2>:
;     bpf_trace_printk("world", 6);
       5:	18 01 00 00 06 00 00 00 00 00 00 00 00 00 00 00	r1 = 0x6 ll
       7:	b7 02 00 00 06 00 00 00	r2 = 0x6
       8:	85 00 00 00 06 00 00 00	call 0x6
; }
       9:	95 00 00 00 00 00 00 00	exit

Disassembly of section xdp:

0000000000000000 <prog>:
;     bpf_trace_printk("%d", 5, x);
       0:	18 01 00 00 0c 00 00 00 00 00 00 00 00 00 00 00	r1 = 0xc ll
       2:	b7 02 00 00 05 00 00 00	r2 = 0x5
       3:	b7 03 00 00 05 00 00 00	r3 = 0x5
       4:	85 00 00 00 06 00 00 00	call 0x6
;     call1();
       5:	85 10 00 00 ff ff ff ff	call -0x1
;     call2();
       6:	85 10 00 00 ff ff ff ff	call -0x1
;     return 0;
       7:	b7 00 00 00 00 00 00 00	r0 = 0x0
       8:	95 00 00 00 00 00 00 00	exit
