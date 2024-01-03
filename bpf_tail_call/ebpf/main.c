#include "vmlinux.h"

#include "bpf_helpers.h"
#include "bpf_tracing.h"
#include "bpf_core_read.h"
#include "bpf_endian.h"

#define ETH_P_IP 0x0800 // IP 数据包的以太网类型

struct {
    __uint(type, BPF_MAP_TYPE_PROG_ARRAY);
    __uint(key_size, sizeof(u32));
    __uint(value_size, sizeof(u32));
    __uint(max_entries, 3);
} packet_processing_progs SEC(".maps");


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
    if (eth->h_proto != bpf_htons(ETH_P_IP)) {
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