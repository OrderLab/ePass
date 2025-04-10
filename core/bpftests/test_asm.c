#include <linux/bpf.h>
#include <bpf/bpf_helpers.h>

int inline spill(int cr, int ci)
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

SEC("xdp")
int prog(void *ctx)
{
	int s = spill(1, 2);
	bpf_printk("%d\n", s);
	return 0;
}

char _license[] SEC("license") = "GPL";
