#include "fill_packet.h"
#include "pcap.h"
#include <arpa/inet.h>
#include <netinet/ip.h>
#include <netinet/ip_icmp.h>
#include <unistd.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/ioctl.h>
#include <time.h>

#include <net/if.h>
void calculate_subnet_range(const char* local_ip, const char* interface, char* start_ip, char* end_ip) {
    struct in_addr ip, mask, start, end;

    // Create a socket to retrieve network information
    int sockfd = socket(AF_INET, SOCK_DGRAM, 0);
    if (sockfd < 0) {
        perror("socket");
        exit(1);
    }
    struct ifreq ifr;
    strncpy(ifr.ifr_name, interface, IFNAMSIZ - 1);
    ifr.ifr_name[IFNAMSIZ - 1] = '\0';
    //get netmask
    if (ioctl(sockfd, SIOCGIFNETMASK, &ifr) < 0) {
        perror("ioctl SIOCGIFNETMASK");
        close(sockfd);
        exit(1);
    }

    struct sockaddr_in* netmask = (struct sockaddr_in*)&ifr.ifr_netmask;
    mask = netmask->sin_addr;

    // change ip and netmask to `in_addr`
    inet_pton(AF_INET, local_ip, &ip);

    //calculate subnet range
    start.s_addr = ip.s_addr & mask.s_addr;
    end.s_addr = start.s_addr | ~mask.s_addr;

    start.s_addr = htonl(ntohl(start.s_addr) + 1); // Skip network address
    end.s_addr = htonl(ntohl(end.s_addr) - 1);     // Skip broadcast address

    // change to string type
    inet_ntop(AF_INET, &start, start_ip, INET_ADDRSTRLEN);
    inet_ntop(AF_INET, &end, end_ip, INET_ADDRSTRLEN);

    close(sockfd);
}
// get the local IP address of the specified interface
void get_network_info(const char* interface, char* local_ip) {
    int sockfd = socket(AF_INET, SOCK_DGRAM, 0);
    if (sockfd < 0) {
        perror("socket");
        exit(1);
    }
    struct ifreq ifr;
    strncpy(ifr.ifr_name, interface, IFNAMSIZ - 1);
    ifr.ifr_name[IFNAMSIZ - 1] = '\0';

    if (ioctl(sockfd, SIOCGIFADDR, &ifr) < 0) {
        perror("ioctl SIOCGIFADDR");
        close(sockfd);
        exit(1);
    }
    struct sockaddr_in* ipaddr = (struct sockaddr_in*)&ifr.ifr_addr;
    strncpy(local_ip, inet_ntoa(ipaddr->sin_addr), INET_ADDRSTRLEN);

    close(sockfd);
}

int main(int argc, char* argv[]) {
    if (argc != 5) {
        fprintf(stderr, "Usage: %s -i <interface_name> -t <timeout>\n", argv[0]);
        return 1;
    }

    char interface[16], local_ip[INET_ADDRSTRLEN];
    char start_ip[INET_ADDRSTRLEN], end_ip[INET_ADDRSTRLEN];
    int timeout = 0;
    pid_t pid = getpid();
    const char* student_id = "M133040076";
    int seq = 1;
    // get network interface and timeout
    for (int i = 1; i < argc; i++) {
        if (strcmp(argv[i], "-i") == 0) {
            strncpy(interface, argv[++i], sizeof(interface) - 1);
            interface[sizeof(interface) - 1] = '\0';
        }
        else if (strcmp(argv[i], "-t") == 0) {
            timeout = atoi(argv[++i]);  //change timeout to int
        }
        else {
            fprintf(stderr, "Invalid argument: %s\n", argv[i]);
            return 1;
        }
    }

    get_network_info(interface, local_ip);
    calculate_subnet_range(local_ip, interface, start_ip, end_ip);
    printf("Scanning range: %s - %s\n", start_ip, end_ip);

    the_pcap_init(interface, timeout);

    int sockfd = socket(AF_INET, SOCK_RAW, IPPROTO_RAW);
    if (sockfd < 0) {
        perror("Failed to create raw socket");
        return 1;
    }
    // Create a raw socket for sending ICMP packets.
    char* packet = malloc(sizeof(struct iphdr) + sizeof(struct icmphdr) + strlen(student_id));
    if (!packet) {
        perror("Failed to allocate memory for packet");
        close(sockfd);
        return 1;
    }
    // Allocate memory for the ICMP packet.
    struct sockaddr_in dst;
    struct in_addr current_addr, start_addr, end_addr, local_addr;
    // convert IP address strings to binary form for local, start, and end IPs.
    if (inet_pton(AF_INET, local_ip, &local_addr) <= 0 ||
        inet_pton(AF_INET, start_ip, &start_addr) <= 0 ||
        inet_pton(AF_INET, end_ip, &end_addr) <= 0) {
        perror("Invalid IP address format");
        free(packet);
        close(sockfd);
        return 1;
    }
    // iterate all IP in subnet range
    for (current_addr.s_addr = start_addr.s_addr;
        ntohl(current_addr.s_addr) <= ntohl(end_addr.s_addr);
        current_addr.s_addr = htonl(ntohl(current_addr.s_addr) + 1)) {
        //skip local IP address
        if (current_addr.s_addr == local_addr.s_addr) continue;
        //convert current IP addr to string format
        char target_ip[INET_ADDRSTRLEN];
        inet_ntop(AF_INET, &current_addr, target_ip, INET_ADDRSTRLEN);
        // initialize the destination address structure.
        memset(&dst, 0, sizeof(dst));
        dst.sin_family = AF_INET;
        if (inet_pton(AF_INET, target_ip, &dst.sin_addr) <= 0) {
            perror("Failed to convert target IP");
            continue;
        }
        // clear the memory allocated for the packet.
        memset(packet, 0, sizeof(struct iphdr) + sizeof(struct icmphdr) + strlen(student_id));
        // fill IP header
        struct iphdr* ip_hdr = (struct iphdr*)packet;
        fill_iphdr(ip_hdr, local_ip, target_ip, sizeof(struct icmphdr) + strlen(student_id));
        // fill ICMP header
        struct icmphdr* icmp_hdr = (struct icmphdr*)(packet + sizeof(struct iphdr));
        fill_icmphdr(icmp_hdr, student_id, seq);

        printf("PING %s (data size = %lu, id = 0x%x, seq = %d, timeout = %d ms)\n",
            target_ip, strlen(student_id), ntohs(icmp_hdr->un.echo.id), seq, timeout);
        // send ICMP packet to target IP
        if (sendto(sockfd, packet, sizeof(struct iphdr) + sizeof(struct icmphdr) + strlen(student_id),
            0, (struct sockaddr*)&dst, sizeof(dst)) < 0) {
            perror("sendto failed");
            exit(1);
        }

        int reply_status = pcap_get_reply(pid, seq, student_id, timeout);
        if (reply_status == 0) {
        //    printf("Received reply from %s\n", target_ip);
        }
        seq++;
    }

    free(packet);
    close(sockfd);
    return 0;
}
