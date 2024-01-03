#include "vmlinux.h"

#include "bpf_helpers.h"
#include "bpf_tracing.h"
#include "bpf_core_read.h"

struct bpf_map_def SEC("maps") shared_data_map = {
    .type = BPF_MAP_TYPE_ARRAY,
    .key_size = sizeof(u32),
    .value_size = sizeof(long),
    .max_entries = 1,
};

SEC("xdp/udp")
int handle_udp(struct xdp_md *ctx) {
    u32 key = 0;
    long *value;

    // Attempt to access the shared data set by the caller program
    value = bpf_map_lookup_elem(&shared_data_map, &key);
    if (value) {
        bpf_printk("Callee program has taken over the execution context. Shared value: %ld\n", *value);
        // Modify the value to show that the callee has executed
        *value = 2;
    }

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
			[0] = &handle_udp,
		},
};


SEC("xdp_classifier")
int packet_classifier(struct xdp_md *ctx)  {
    u32 key = 0;
    long value = 1;  // Set a value to share with the callee program

    // Set the shared value before making the tail call
    bpf_map_update_elem(&shared_data_map, &key, &value, BPF_ANY);
    bpf_printk("Caller program before tail call. Shared value set to: %ld\n", value);

    // Perform the tail call
    bpf_tail_call(ctx, &packet_processing_progs, 0);

    // This line should not be printed if the tail call is successful
    bpf_printk("Caller program after tail call - this should not be printed if tail call was successful.\n");

    return XDP_DROP; // Default action if tail call fails
}

char _license[] SEC("license") = "GPL";