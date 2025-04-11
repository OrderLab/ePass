#include <linux/bpf.h>
#include <bpf/bpf_helpers.h>

int __always_inline spill(int cr, int ci)
{
	int i = 1;
	int zr = cr;
	int zi = ci;
	int zk = cr + ci;
	int zl = cr - ci;

	while (i < 10) {
		int t = zr * zr - zi * zi + cr;
		zr = t;
		zi = 2 * zr * zi + ci;
		zk = 3 * zr - zi * zk * zr;
		zl = zl + 1;

		i = i + 1;
	}
	return zl + zk + zi + zr + ci + cr;
}

SEC("xdp")
int prog(void *ctx)
{
	int tot = 0;
	for (int i = 0; i < 10; ++i) {
		for (int j = i; j < 10; ++j) {
			int s = spill(i, j);
			bpf_printk("%d %d: %d\n", i, j, s);
			tot += s;
		}
	}
	bpf_printk("tot: %d\n", tot);
    // 1535866789

	return 0;
}


char _license[] SEC("license") = "GPL";
