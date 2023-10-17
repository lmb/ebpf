// kprobe_simple {
//go:build ignore

#include <linux/bpf.h>
#include <asm/ptrace.h> // for struct pt_regs
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>

int fill_filename(char *dst, unsigned int size, struct pt_regs *src);

SEC("kprobe/sys_execve")
int kprobe_simple(struct pt_regs *ctx) {
	char filename[128];

	if (fill_filename(filename, sizeof(filename), ctx) > 0) {
		bpf_printk("execve: %s\n", filename);
	}

	return 0;
}

char __license[] SEC("license") = "Dual MIT/GPL";

// }

// fill_filename_def {

int fill_filename(char *dst, unsigned int size, struct pt_regs *ctx) {
	void *user_filename = (void *)PT_REGS_PARM1(ctx);

	return bpf_probe_read_user_str(dst, size, user_filename);
}

// }

// kprobe_macro_def {

SEC("kprobe/sys_execve")
int BPF_KPROBE(kprobe_macro, char *user_filename) {
	char filename[128];

	if (bpf_probe_read_user_str(filename, sizeof(filename), user_filename) > 0) {
		bpf_printk("execve: %s\n", filename);
	}

	return 0;
}

// }
