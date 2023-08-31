#include <vmlinux.h>

#include "bpf/bpf_helpers.h"
#include "bpf/bpf_tracing.h"
#include "bpf/bpf_core_read.h"

struct {
	__uint(type, BPF_MAP_TYPE_RINGBUF);
	__uint(max_entries, 1 << 24);
} events SEC(".maps");

struct task_info {
	u32 pid;
	u8 comm[80];
};

SEC("kprobe/vfs_mkdir")
int kprobe_vfs_mkdir(void *ctx)
{
    bpf_printk("mkdir (vfs hook point) by using ringbuf_map\n");
    struct task_info *task_data;
    task_data = bpf_ringbuf_reserve(&events, sizeof(*task_data), 0);
    if (!task_data) {
        bpf_printk("ringbuf_reserve failed\n");
        return 0;
    }
    task_data->pid = bpf_get_current_pid_tgid() >> 32;
    bpf_get_current_comm(&task_data->comm, sizeof(task_data->comm));
    bpf_printk("pid: %d, comm: %s\n", task_data->pid, task_data->comm);
    bpf_ringbuf_submit(task_data, 0);
    return 0;
};

char _license[] SEC("license") = "GPL";
__u32 _version SEC("version") = 0xFFFFFFFE;