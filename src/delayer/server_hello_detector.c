#include <uapi/linux/ptrace.h>
#include <net/sock.h>
#include <net/inet_sock.h>
#include <bcc/proto.h>

#define IP_TCP 	 6
#define IP_UDP   17
#define ETH_HLEN 14
#define UDP_HLEN 8


int server_hello_detector(struct xdp_md *ctx) {
    void* data_end = (void*)(long)ctx->data_end;
    void* data = (void*)(long)ctx->data;
    struct ethhdr *eth = data;

    ctx->tstamp = bpf_ktime_get_ns() + 5000000000;


    return XDP_PASS;
}
