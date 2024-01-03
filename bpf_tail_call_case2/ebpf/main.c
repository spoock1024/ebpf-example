#include "vmlinux.h"

#include "bpf_helpers.h"
#include "bpf_tracing.h"
#include "bpf_core_read.h"

SEC("xdp/icmp")
int handle_icmp(struct xdp_md *ctx) {
    // ICMP包的处理逻辑
    bpf_printk("new icmp packet captured (XDP)\n");
    return XDP_PASS;
}

SEC("xdp/tcp")
int handle_tcp(struct xdp_md *ctx) {
    // TCP包的处理逻辑
    bpf_printk("new tcp packet captured (XDP)\n");
    return XDP_PASS;
}

SEC("xdp/udp")
int handle_udp(struct xdp_md *ctx) {
    // UDP包的处理逻辑
    bpf_printk("new udp packet captured (XDP)\n");
    return XDP_PASS;
}

struct {
	__uint(type, BPF_MAP_TYPE_PROG_ARRAY);
	__type(key, u32);
	__type(value, u32);
	__uint(max_entries, 3);
	__array(values, int());
} packet_processing_progs SEC(".maps") = {
	.values =
		{
			[0] = &handle_icmp,
			[1] = &handle_tcp,
			[2] = &handle_udp,
		},
};


SEC("xdp_classifier")
int packet_classifier(struct xdp_md *ctx)  {
//    bpf_printk("new packet_classifier (XDP)\n");
    void *data_end = (void *)(long)ctx->data_end;
    void *data = (void *)(long)ctx->data;
    struct ethhdr *eth = data;
    struct iphdr *ip;

    // 检查是否有足够的数据空间
    if ((void *)(eth + 1) > data_end) {
        return XDP_ABORTED;
    }

    // 确保这是一个IP包
    if (eth->h_proto != 8) {
        return XDP_PASS;
    }

    ip = (struct iphdr *)(eth + 1);

    // 检查IP头部是否完整
    if ((void *)(ip + 1) > data_end) {
        return XDP_ABORTED;
    }
    bpf_printk("protocol: %d\n", ip->protocol);
    bpf_printk("icmp: %d,tcp:%d,udp:%d\n", IPPROTO_ICMP, IPPROTO_TCP, IPPROTO_UDP);
    switch (ip->protocol) {
        case IPPROTO_ICMP:
            bpf_printk("icmp\n");
            bpf_tail_call(ctx, &packet_processing_progs, 0);
            break;
        case IPPROTO_TCP:
            bpf_printk("tcp\n");
            bpf_tail_call(ctx, &packet_processing_progs, 1);
            break;
        case IPPROTO_UDP:
            bpf_printk("udp\n");
            bpf_tail_call(ctx, &packet_processing_progs, 2);
            break;
        default:
            bpf_printk("unknown protocol\n");
            break;
    }

    return XDP_PASS;
}

char _license[] SEC("license") = "GPL";