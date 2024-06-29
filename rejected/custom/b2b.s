
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
       0:	b7 01 00 00 68 69 00 00	r1 = 0x6968
;     char s1[] = "hi";
       1:	6b 1a fc ff 00 00 00 00	*(u16 *)(r10 - 0x4) = r1
       2:	b7 01 00 00 00 00 00 00	r1 = 0x0
       3:	73 1a fe ff 00 00 00 00	*(u8 *)(r10 - 0x2) = r1
       4:	bf a1 00 00 00 00 00 00	r1 = r10
       5:	07 01 00 00 fc ff ff ff	r1 += -0x4
;     bpf_trace_printk(s1, sizeof(s1));
       6:	b7 02 00 00 03 00 00 00	r2 = 0x3
       7:	85 00 00 00 06 00 00 00	call 0x6
;     call1();
       8:	85 10 00 00 ff ff ff ff	call -0x1
;     call2();
       9:	85 10 00 00 ff ff ff ff	call -0x1
;     return 0;
      10:	b7 00 00 00 00 00 00 00	r0 = 0x0
      11:	95 00 00 00 00 00 00 00	exit
