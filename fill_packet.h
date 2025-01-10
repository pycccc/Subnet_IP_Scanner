#ifndef __FILLPACKET__H_
#define __FILLPACKET__H_

#include <netinet/ip.h>
#include <netinet/ip_icmp.h>

typedef char u8;
typedef unsigned short u16;

#define PACKET_SIZE    92
#define IP_OPTION_SIZE 8
#define ICMP_PACKET_SIZE   PACKET_SIZE - (int)sizeof(struct ip) - IP_OPTION_SIZE
#define ICMP_DATA_SIZE     ICMP_PACKET_SIZE - (int)sizeof(struct icmphdr)
#define DEFAULT_SEND_COUNT 4
#define DEFAULT_TIMEOUT 1500

typedef struct
{
	struct ip ip_hdr;
	u8 ip_option[8];
	struct icmphdr icmp_hdr;
	u8 data[0];
} myicmp ;

void fill_iphdr(struct iphdr* ip_hdr, const char* src_ip, const char* dst_ip, int payload_len);

void fill_icmphdr (struct icmphdr *icmp_hdr, const char * data, int seq);

u16 fill_cksum ( u16 *addr, int len);
 
#endif
 