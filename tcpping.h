#ifndef __TCPPING_H__
#define __TCPPING_H__

#include <netinet/ip.h>


#define tcp_flag_isset(tcpptr, flag) (((tcpptr->th_flags) & (flag)) == (flag))

/* Define the types of packets that we're sniffing for on the wire */
#define UNINTERESTING 0
#define SYN_FROM_US 1
#define SYNACK_FROM_THEM 2
#define ICMP_TIMEEXCEEDED 3

#define F_QUIET 0x010

#define MAX_PAYLOAD_S 1460
#define PACKET_HISTORY 1461 
#define MAX_HOST 1024 

u_short dest_port = 80;
struct in_addr src_ip;

int options = 0;
int verbose = 0;
int notify_fd;

int ttl = 64;
int timeout = 1000;
int host_num = 0;
int sequence_offset = 0;

int payload_s = 0;
u_char payload[MAX_PAYLOAD_S] = {'f','a','s','t'};


char *myname = NULL;
char *filename = NULL;

pid_t child_pid;
struct timeval tv_timxceed;


/* Global handle to libnet -- libnet1 requires only one instantiation per process */
libnet_t *l;
libnet_ptag_t tcp_pkt;
libnet_ptag_t ip_pkt;

/* Keep track of a recent history of packet send times to accurately calculate
 * when packets were received
 */

struct timeval sent_times[PACKET_HISTORY];

typedef struct host_entry
{
char *dest_name;
char *dest_quad;
in_addr_t dest_ip;

long long sum_ping;
long long sum_ping2;

float min_ping;
float avg_ping;
float max_ping;
float mdev_ping;

int total_syns;
int total_synacks;
int total_rsts;

int successful_pings;
} HOST_ENTRY;

HOST_ENTRY host_array[MAX_HOST];

char* find_device(char *dq);
char *find_source_ip(char *dq);

void add_host(char *dst_host);

void cmb_filter(char *filter_expression, int length);

void sniff_packets(char *device_name);

void inject_syn_packet(int sequence, HOST_ENTRY *tp_host);

void got_packet(u_char *args, const struct pcap_pkthdr *header, const u_char *packet);

int get_packet_type(struct ip *ip, struct tcphdr *tcp, struct icmp *icmp);

int cmp_addr(struct in_addr addr);

HOST_ENTRY *get_host(struct in_addr addr);

#endif
