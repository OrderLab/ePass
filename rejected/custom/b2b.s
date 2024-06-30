
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
       0:	b7 01 00 00 64 00 00 00	r1 = 0x64
;     char s1[] = "hello world my friend";
       1:	6b 1a fc ff 00 00 00 00	*(u16 *)(r10 - 0x4) = r1
       2:	b7 01 00 00 72 69 65 6e	r1 = 0x6e656972
       3:	63 1a f8 ff 00 00 00 00	*(u32 *)(r10 - 0x8) = r1
       4:	18 01 00 00 72 6c 64 20 00 00 00 00 6d 79 20 66	r1 = 0x6620796d20646c72 ll
       6:	7b 1a f0 ff 00 00 00 00	*(u64 *)(r10 - 0x10) = r1
       7:	18 01 00 00 68 65 6c 6c 00 00 00 00 6f 20 77 6f	r1 = 0x6f77206f6c6c6568 ll
       9:	7b 1a e8 ff 00 00 00 00	*(u64 *)(r10 - 0x18) = r1
      10:	bf a1 00 00 00 00 00 00	r1 = r10
      11:	07 01 00 00 e8 ff ff ff	r1 += -0x18
;     bpf_trace_printk(s1, sizeof(s1));
      12:	b7 02 00 00 16 00 00 00	r2 = 0x16
      13:	85 00 00 00 06 00 00 00	call 0x6
;     call1();
      14:	85 10 00 00 ff ff ff ff	call -0x1
;     call2();
      15:	85 10 00 00 ff ff ff ff	call -0x1
;     return 0;
      16:	b7 00 00 00 00 00 00 00	r0 = 0x0
      17:	95 00 00 00 00 00 00 00	exit
