
b2b.o:	file format elf64-bpf

Disassembly of section .text:

0000000000000000 <call1>:
;     bpf_trace_printk("hello world", 2);
       0:	18 01 00 00 00 00 00 00 00 00 00 00 00 00 00 00	r1 = 0x0 ll
       2:	b7 02 00 00 02 00 00 00	r2 = 0x2
       3:	85 00 00 00 06 00 00 00	call 0x6
; }
       4:	95 00 00 00 00 00 00 00	exit

0000000000000028 <call2>:
;     bpf_trace_printk("world", 6);
       5:	18 01 00 00 0c 00 00 00 00 00 00 00 00 00 00 00	r1 = 0xc ll
       7:	b7 02 00 00 06 00 00 00	r2 = 0x6
       8:	85 00 00 00 06 00 00 00	call 0x6
; }
       9:	95 00 00 00 00 00 00 00	exit

Disassembly of section xdp:

0000000000000000 <prog>:
; int prog(void *ctx) {
       0:	b7 01 00 00 31 00 00 00	r1 = 0x31
;     char s1[] = "1";
       1:	6b 1a fe ff 00 00 00 00	*(u16 *)(r10 - 0x2) = r1
       2:	bf a1 00 00 00 00 00 00	r1 = r10
       3:	07 01 00 00 fe ff ff ff	r1 += -0x2
;     bpf_trace_printk(s1, sizeof(s1));
       4:	b7 02 00 00 02 00 00 00	r2 = 0x2
       5:	85 00 00 00 06 00 00 00	call 0x6
;     call1();
       6:	85 10 00 00 ff ff ff ff	call -0x1
;     call2();
       7:	85 10 00 00 ff ff ff ff	call -0x1
;     return 0;
       8:	b7 00 00 00 00 00 00 00	r0 = 0x0
       9:	95 00 00 00 00 00 00 00	exit
