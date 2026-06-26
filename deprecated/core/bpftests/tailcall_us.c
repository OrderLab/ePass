// tailcall_user.c
#include <stdio.h>
#include <bpf/libbpf.h>
#include <bpf/bpf.h>
#include <unistd.h>
int main()
{
	struct bpf_object *obj;
	struct bpf_program *p_entry, *p_next;
	int prog_fd_entry, prog_fd_next;
	int map_fd;

	obj = bpf_object__open_file("output/tailcall.o", NULL);
	if (!obj) {
		printf("open failed\n");
		return 1;
	}

	if (bpf_object__load(obj)) {
		printf("load failed\n");
		return 1;
	}

	p_entry = bpf_object__find_program_by_name(obj, "entry_prog");
	p_next = bpf_object__find_program_by_name(obj, "next_prog");

	prog_fd_entry = bpf_program__fd(p_entry);
	prog_fd_next = bpf_program__fd(p_next);

	map_fd = bpf_object__find_map_fd_by_name(obj, "jmp_table");

	__u32 index = 1;
	if (bpf_map_update_elem(map_fd, &index, &prog_fd_next, 0)) {
		printf("update_elem failed\n");
		return 1;
	}

	struct bpf_link *link1 = NULL, *link2 = NULL, *link3 = NULL;

	link1 = bpf_program__attach_tracepoint(p_entry, "syscalls",
					       "sys_enter_mount");
	if (libbpf_get_error(link1)) {
		fprintf(stderr, "Failed to attach\n");
		return 1;
	}
	sleep(30);
	bpf_link__destroy(link1);
	return 0;
}
