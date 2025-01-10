#include "fill_packet.h"
#include <string.h>
#include <arpa/inet.h>
#include <netinet/ip.h>
#include <netinet/ip_icmp.h>
#include <unistd.h>
#include <sys/time.h> 

// Calculate the checksum for the given address and length
u16 fill_cksum(u16* addr, int len) {
    int sum = 0;
    u16 answer = 0;
    u16* w = addr;
    int nleft = len;

    // Add each 16-bit segment to the sum
    while (nleft > 1) {
        sum += *w++;
        nleft -= 2;
    }

    // If there's one byte left, add it as well
    if (nleft == 1) {
        *(unsigned char*)(&answer) = *(unsigned char*)w;
        sum += answer;
    }

    // Fold the sum to 16 bits and compute its complement
    sum = (sum >> 16) + (sum & 0xffff);
    sum += (sum >> 16);
    answer = ~sum;
    return answer;
}
//fill ICMP header
void fill_icmphdr(struct icmphdr* icmp_hdr, const char* data, int seq) {
    icmp_hdr->type = ICMP_ECHO;  // ICMP Echo Request
    icmp_hdr->code = 0;          // Code is always 0 for echo request
    icmp_hdr->checksum = 0;      // Initialize checksum to 0
    icmp_hdr->un.echo.id = htons(getpid() & 0xFFFF); // Use process ID as identifier
    icmp_hdr->un.echo.sequence = htons(seq);         // Set sequence number

    // Copy the payload data (only student ID) into the ICMP packet
    memcpy((char*)(icmp_hdr + 1), data, strlen(data));

    // Calculate the checksum for the entire ICMP packet
    icmp_hdr->checksum = fill_cksum(
        (u16*)icmp_hdr, sizeof(struct icmphdr) + strlen(data));
}

// fill the IP header 
void fill_iphdr(struct iphdr* ip_hdr, const char* src_ip, const char* dest_ip, int payload_len) {
    ip_hdr->version = 4;           // IPv4
    ip_hdr->ihl = 5;               // Header length (5 * 4 = 20 bytes)
    ip_hdr->tos = 0;               // Type of Service (default 0)
    ip_hdr->tot_len = htons(sizeof(struct iphdr) + payload_len); // Total length
    ip_hdr->id = htons(0);         // Identification field
    ip_hdr->frag_off = 0;          // No fragmentation
    ip_hdr->ttl = 1;              
    ip_hdr->protocol = IPPROTO_ICMP; // Protocol is ICMP
    ip_hdr->check = 0;             // Initialize checksum to 0
    ip_hdr->saddr = inet_addr(src_ip);  // Source IP
    ip_hdr->daddr = inet_addr(dest_ip); // Destination IP

    // Calculate the checksum for the IP header
    ip_hdr->check = fill_cksum((u16*)ip_hdr, sizeof(struct iphdr));
}
