#include <uapi/linux/ptrace.h>
#include <net/sock.h>
#include <net/inet_sock.h>
#include <bcc/proto.h>

#define IP_TCP 	 6
#define IP_UDP   17
#define ETH_HLEN 14
#define UDP_HLEN 8

struct ipv4_tuple_t {
    u32 saddr;
    u32 daddr;
    u16 sport;
    u16 dport;
};

struct process_t {
    u32 pid;
    char comm[16];
};

// Hash tables
BPF_HASH(connectsock, pid_t, struct sock *, 10240);
BPF_HASH(tuplepid_ipv4, struct ipv4_tuple_t, struct process_t, 10240);

BPF_HASH(tcp_sessions, struct ipv4_tuple_t, char, 10240);
BPF_HASH(quic_sessions, struct ipv4_tuple_t, char, 10240);

// Helper function to parse sock struct
static int read_ipv4_tuple(struct ipv4_tuple_t *tuple, struct sock *skp)
{
  u32 saddr = bpf_ntohl(skp->__sk_common.skc_rcv_saddr);
  u32 daddr = bpf_ntohl(skp->__sk_common.skc_daddr);
  struct inet_sock *sockp = (struct inet_sock *)skp;
  u16 sport = bpf_ntohs(sockp->inet_sport);
  u16 dport = bpf_ntohs(skp->__sk_common.skc_dport);
  tuple->saddr = saddr;
  tuple->daddr = daddr;
  tuple->sport = sport;
  tuple->dport = dport;
  // if addresses or ports are 0, ignore
  if (saddr == 0 || daddr == 0 || sport == 0 || dport == 0) {
    return 0;
  }
  return 1;
}


// Store sk address in connectsock table on socket connect
int trace_connect_v4_entry(struct pt_regs *ctx, struct sock *sk)
{
  pid_t pid = bpf_get_current_pid_tgid() >> 32;  // returns u64 but we care only about pid
  connectsock.update(&pid, &sk);
  return 0;
}

// Store sk address in connectsock table on socket connect
int trace_ip4_datagram_connect(struct pt_regs *ctx, struct sock *skp, struct sockaddr *sa)
{
  // There is a lot of UDP packets, e.g., for DNS
  // So we ignore all packets with dport != 443
  struct sockaddr_in *sa_in = (struct sockaddr_in *)sa;
  u16 dport = bpf_ntohs(sa_in->sin_port);
  if (dport != 443) {
    return 0;
  }

  struct inet_sock *inet = inet_sk(skp);
  u32 daddr = bpf_ntohl(sa_in->sin_addr.s_addr);
  u32 saddr = bpf_ntohl(inet->inet_saddr);  // FIXME: equal to 0?
  u16 sport = bpf_ntohs(inet->inet_sport);
  
  struct ipv4_tuple_t tuple = {};
  tuple.saddr = saddr;
  tuple.sport = sport;
  tuple.daddr = daddr;
  tuple.dport = dport; 
  
  struct process_t p = {};
  pid_t pid = bpf_get_current_pid_tgid() >> 32;
  p.pid = pid;
  bpf_get_current_comm(&p.comm, sizeof(p.comm));

  bpf_trace_printk("trace_ip4_datagram_connect: saddr=%u, daddr=%u\n", tuple.saddr, tuple.daddr);
  bpf_trace_printk("trace_ip4_datagram_connect: sport=%u, dport=%u\n", tuple.sport, tuple.dport);
  bpf_trace_printk("trace_ip4_datagram_connect: pid=%u\n", p.pid);

  tuplepid_ipv4.update(&tuple, &p);
  return 0;
}

// Store ipv4_tuple_t in tuplepid_ipv4 when socket connect is done
int trace_connect_v4_return(struct pt_regs *ctx)
{
  int ret = PT_REGS_RC(ctx);
  if (ret != 0) {
    // failed to send SYNC packet, may not have populated
    // socket __sk_common.{skc_rcv_saddr, ...}
    return 0;
  }

  pid_t pid = bpf_get_current_pid_tgid() >> 32;
  struct sock **skpp;
  skpp = connectsock.lookup(&pid);
  if (skpp == 0) {
    return 0;  // missed entry
  }
  connectsock.delete(&pid);

  // pull in details
  struct sock *skp = *skpp;
  struct ipv4_tuple_t tuple = {};
  if (!read_ipv4_tuple(&tuple, skp)) {
      return 0;
  }

  // bpf_trace_printk("trace_connect_v4_return: saddr=%u, daddr=%u\n", tuple.saddr, tuple.daddr);
  // bpf_trace_printk("trace_connect_v4_return: sport=%u, dport=%u\n", tuple.sport, tuple.dport);
  
  struct process_t p = {};
  p.pid = pid;
  bpf_get_current_comm(&p.comm, sizeof(p.comm));

  tuplepid_ipv4.update(&tuple, &p);
  return 0;
}


struct tls_event_t {
  u8  type;  // 1 = ClientHello, 2 = First Application Data
  u64 ts_ns;
  u32 pid;  // 0 if not found
  char comm[16];
  u32 saddr;
  u32 daddr;
  u16 sport;
  u16 dport;
};
BPF_RINGBUF_OUTPUT(tls_events, 8);

struct quic_event_t {
  u8  type;  // 1 = QUIC Initial, 2 = First packet with short header
  u64 ts_ns;
  u32 pid;  // 0 if not found
  char comm[16];
  u32 saddr;
  u32 daddr;
  u16 sport;
  u16 dport;
  char cid_server[16];  // Not used at the moment
  char cid_client[16];
};
BPF_RINGBUF_OUTPUT(quic_events, 8);


// process_network_event doesn't run in the context of the process that initiated the
// connection so we need to store a map TUPLE -> PID to send the right PID on
// the event
static int process_network_event(
    struct __sk_buff *skb,
    uint8_t  event_type,
    uint32_t saddr,
    uint32_t daddr,
    uint16_t sport,
    uint16_t dport) {

  struct ipv4_tuple_t tuple = {};
  tuple.saddr = saddr;
  tuple.daddr = daddr;
  tuple.sport = sport;
  tuple.dport = dport;

  // bpf_trace_printk("process_network_event: event_type=%d\n", event_type);
  // bpf_trace_printk("process_network_event: saddr=%u, daddr=%u\n", tuple.saddr, tuple.daddr);
  // bpf_trace_printk("process_network_event: sport=%u, dport=%u\n", tuple.sport, tuple.dport);

  u32 pid;
  struct process_t *processp;
  processp = tuplepid_ipv4.lookup(&tuple);
  if (processp != NULL) {
    pid = processp->pid; 
  } else {
    // missed entry
    pid = 0;
    // Except for debugging, you should avoid passing events with pid=0 to user space to reduce pipe usage
    return 0;
  }
  // bpf_trace_printk("process_network_event: pid=%u\n", pid); 

  struct tls_event_t event = {};
  event.type = event_type;
  event.ts_ns = bpf_ktime_get_ns();
  event.pid = pid;
  bpf_probe_read_kernel(&event.comm, 16, &processp->comm);
  event.saddr = saddr;
  event.daddr = daddr;
  event.sport = sport;
  event.dport = dport;

  tls_events.ringbuf_output(&event, sizeof(event), BPF_RB_FORCE_WAKEUP);

	return 0;
}


/*
    Filter IP and TCP packets, having payload not empty
    and are interesting TLS records (i.e., ClientHello, ChangeCipherSpec, Application Data)
    This will call process_network_event() for each interesting TLS record

    If the program is loaded as PROG_TYPE_SOCKET_FILTER and attached to a socket:
    return  0 -> DROP the packet
    return -1 -> KEEP the packet and return it to user space (userspace can read it from the socket_fd)
*/
int tls_handshake_detector(struct __sk_buff *skb) {
  // TODO: Test if source address is routable
  // If yes, it's Server->Client packet: ignore it
  // (we need only C->S packets)

	u8 *cursor = 0;
  u32 ip_header_length = 0;

  // TODO: support packets without ETH layer (e.g., tun interface)
	struct ethernet_t *ethernet = cursor_advance(cursor, sizeof(*ethernet));
  // Keep only IP packets (ethernet type = 0x0800)
	if (!(ethernet->type == 0x0800)) {
		return 0;
	}

	struct ip_t *ip = cursor_advance(cursor, sizeof(*ip));

  // Calculate ip header length
	// value to multiply * 4
	// e.g. ip->hlen = 5 ; IP Header Length = 5 x 4 bytes = 20 bytes
	ip_header_length = ip->hlen << 2;   // SHL 2 -> *4 multiply

  // Check ip header length against minimum
	if (ip_header_length < sizeof(*ip)) {
		return 0;
	}

  // Shift cursor forward for dynamic ip header size
  void *_ = cursor_advance(cursor, (ip_header_length-sizeof(*ip)));

  // ###############################################################
  // ## TCP processing
  // ###############################################################
  if (ip->nextp == IP_TCP) {
    u32 tcp_header_length = 0;
    u32 payload_offset = 0;
    u32 payload_length = 0;

    struct tcp_t *tcp = cursor_advance(cursor, sizeof(*tcp));

    // Calculate tcp header length
    // value to multiply *4
    // e.g. tcp->offset = 5 ; TCP Header Length = 5 x 4 bytes = 20 bytes
    tcp_header_length = tcp->offset << 2;   // SHL 2 -> *4 multiply

    // Calculate payload offset and length
    payload_offset = ETH_HLEN + ip_header_length + tcp_header_length;
    payload_length = ip->tlen - ip_header_length - tcp_header_length;

    // We will read 6 bytes, so ignore packets with less than 6 bytes
    if(payload_length < 6) {
      return 0;
    }

    // TLS record is
    // 1 byte: Content Type (0x16 = handshake)
    // 2 bytes: Version (0x0301 = TLS 1.0, 0x0303 = TLS 1.2) (!) ClientHello usually uses TLS 1.0 even for newer versions 
    // 2 bytes: Length
    // 1 byte: Handshake Type (0x01 = Client Hello)

    // Load first 6 bytes of payload into p (payload_array)
    unsigned long p[6];
    for (int i = 0; i < 6; i++) {
      p[i] = load_byte(skb, payload_offset + i);
    }
    
    // Content type is handshake and handshake type is client hello
    if ((p[0] == 0x16) && (p[5] == 0x01)) {
        bpf_trace_printk("Client Hello\n");

        process_network_event(
          skb,
          0,  // BeginTlsHs
          ip->src,  // unsigned int
          ip->dst,  // unsigned int
          tcp->src_port,  // unsigned short
          tcp->dst_port);  // unsigned short

        // Add session
        char session_state = 1;
        struct ipv4_tuple_t tuple = {};
        tuple.saddr = ip->src;
        tuple.daddr = ip->dst;
        tuple.sport = tcp->src_port;
        tuple.dport = tcp->dst_port;

        tcp_sessions.update(&tuple, &session_state);
        
        return 0;
    }

    // Content type is Application Data
    if (p[0] == 0x17) {
        bpf_trace_printk("Application Data\n");

        struct ipv4_tuple_t tuple = {};
        tuple.saddr = ip->src;
        tuple.daddr = ip->dst;
        tuple.sport = tcp->src_port;
        tuple.dport = tcp->dst_port;

        // As ClientHello is Client->Server, we will only match App data C->S here
        char *session_state = tcp_sessions.lookup(&tuple);
        if ((session_state != NULL) && (*session_state == 1)) {
          bpf_trace_printk("Session found: sending end event\n");

          process_network_event(
            skb,
            1,  // EndTlsHs
            ip->src,
            ip->dst,
            tcp->src_port,
            tcp->dst_port);        

          // Delete session to avoid sending end event on each app data packet
          tcp_sessions.delete(&tuple);
        }

        return 0;
    }

    return 0;
  }

  // ###############################################################
  // ## UDP processing
  // ###############################################################
	if (ip->nextp == IP_UDP) {
    u32 payload_offset = 0;
    u32 payload_length = 0;

    struct udp_t *udp = cursor_advance(cursor, sizeof(*udp));

    // Calculate payload offset and length
    payload_offset = ETH_HLEN + ip_header_length + UDP_HLEN;
    payload_length = ip->tlen - ip_header_length - UDP_HLEN;

    /*
    Long header fields are (in bytes): 1 - 4 - 1 - up to 20 - 1 - up to 20 - ...
    
    Long Header Packet {
      Header Form (1) = 1,
      Fixed Bit (1) = 1,
      Long Packet Type (2),
      Type-Specific Bits (4),
      Version (32),
      [...]
    }

    Note on fixed bit: Even though this bit is fixed in the version 1 specification,
    endpoints might use an extension that varies the bit [QUIC-GREASE]
    */

    if (payload_length < 5) {
      return 0;
    }
    char p[5];
    for (int i = 0; i < 5; i++) {
      p[i] = load_byte(skb, payload_offset + i);
    }

    
    // Check if it's a QUIC Initial/Handshake packet with Version field equal to 1
    // First byte: Initial 1.00.... ; HS 1.10....
    // (p[0] & 0x90) == 0x80 => 1..0.... & 10010000 == 10000000
    if ((p[0] & 0x90) == 0x80 && p[1] == 0x00 && p[2] == 0x00 && p[3] == 0x00 && p[4] == 0x01) {
        bpf_trace_printk("QUIC v1 Initial/HS packet detected\n");

        // process_network_event(
        //   skb,
        //   0,  // BeginTlsHs
        //   ip->src,  // unsigned int
        //   ip->dst,  // unsigned int
        //   tcp->src_port,  // unsigned short
        //   tcp->dst_port);  // unsigned short

        // Add session
        char session_state = 1;
        struct ipv4_tuple_t tuple = {};
        tuple.saddr = ip->src;
        tuple.daddr = ip->dst;
        tuple.sport = udp->sport;
        tuple.dport = udp->dport;

        quic_sessions.update(&tuple, &session_state);
        
        return 0;
    }

    // Short header = traffic secrets are used (then stored in memory)
    // Short header = 01......
    // (p[0] & 0x90) == 0x80 => 1..0.... & 10010000 == 10000000
    if (0) {  // TODO
        bpf_trace_printk("QUIC short header detected\n");

        struct ipv4_tuple_t tuple = {};
        tuple.saddr = ip->src;
        tuple.daddr = ip->dst;
        tuple.sport = udp->sport;
        tuple.dport = udp->dport;

        // As ClientHello is Client->Server, we will only match App data C->S here
        char *session_state = quic_sessions.lookup(&tuple);
        if ((session_state != NULL) && (*session_state == 1)) {
          bpf_trace_printk("Session found: sending end event\n");

          // process_network_event(
          //   skb,
          //   1,  // EndTlsHs
          //   ip->src,
          //   ip->dst,
          //   tcp->src_port,
          //   tcp->dst_port);        

          // Delete session to avoid sending end event on each app data packet
          quic_sessions.delete(&tuple);
        }

        return 0;
    }
  }

  // Don't send the packet to user space
  return 0;
}
