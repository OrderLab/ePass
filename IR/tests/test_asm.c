#include <linux/bpf.h>
#include <bpf/bpf_helpers.h>

int __noinline spill(int cr, int ci)
{
	int i = 0;
	int zr = 0;
	int zi = 0;
	int zk = 0;
	int zl = 0;

	while (i < 100 &&
	       zr * zr + zi * zi + zk * zk - zl * zl * (zi - 1) < 4) {
		int t = zr * zr - zi * zi + cr;
		zi = 2 * zr * zi + ci;
		zr = t;
		zk = 3 * zr - zi * zi * zk * zr;
		zl = zl + 1;

		i = i + 1;
	}
	return i;
}

void __noinline pk(char s)
{
	bpf_trace_printk("%c", 1, s);
}

void __noinline pk_l(char *s)
{
	bpf_trace_printk("%s", 1, s);
}

SEC("xdp")
int prog(void *ctx)
{
	int s = spill(1, 2);
	static char ores[10] = "helloggg";
	static char res[10] = "helloworld";
	for (int i = 0; i < 10; ++i) {
		pk(res[i]);
	}
	pk_l(res);
	pk_l(ores);
	pk(res[0]);
	res[0] = s;
	return 0;
}

char _license[] SEC("license") = "GPL";
