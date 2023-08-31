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
    struct task_info task_data = {};
    u64 id   = bpf_get_current_pid_tgid();
    u32 tgid = id >> 32;
    task_data.pid = tgid;
    bpf_get_current_comm(&task_data.comm, 80);
    bpf_printk("pid: %d\n", tgid);
    bpf_printk("comm: %s\n", task_data.comm);
    bpf_ringbuf_output(&events,&task_data, sizeof(task_data), 0 /* flags */);
    return 0;
};

char _license[] SEC("license") = "GPL";
__u32 _version SEC("version") = 0xFFFFFFFE;