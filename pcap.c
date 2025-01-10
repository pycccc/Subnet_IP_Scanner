#include "pcap.h"
#include <sys/types.h>
#include <pcap/pcap.h>
#include <netinet/in.h>
#include <string.h>
#include <unistd.h>

static const char* dev;
static char* net;
static char* mask;

static char filter_string[FILTER_STRING_SIZE] = "";

static pcap_t* p;
static struct pcap_pkthdr hdr;

/*
 * Initialize pcap with the correct interface and filter
 */
void the_pcap_init(const char* interface_name, int timeout) {
    int ret;
    char errbuf[PCAP_ERRBUF_SIZE];

    bpf_u_int32 netp;
    bpf_u_int32 maskp;

    struct in_addr addr;

    struct bpf_program fcode;

    dev = interface_name;

    ret = pcap_lookupnet(dev, &netp, &maskp, errbuf);
    if (ret == -1) {
        fprintf(stderr, "%s\n", errbuf);
        exit(1);
    }

    addr.s_addr = netp;
    net = inet_ntoa(addr);
    if (net == NULL) {
        perror("inet_ntoa");
        exit(1);
    }

    addr.s_addr = maskp;
    mask = inet_ntoa(addr);
    if (mask == NULL) {
        perror("inet_ntoa");
        exit(1);
    }

    p = pcap_create(dev, errbuf);
    if (!p) {
        fprintf(stderr, "pcap_create failed: %s\n", errbuf);
        exit(1);
    }

    if (pcap_set_snaplen(p, BUFSIZ) != 0) {
        pcap_perror(p, "pcap_set_snaplen");
        exit(1);
    }

    if (pcap_set_promisc(p, 1) != 0) {
        pcap_perror(p, "pcap_set_promisc");
        exit(1);
    }

    if (pcap_set_timeout(p, timeout) != 0) {
        pcap_perror(p, "pcap_set_timeout");
        exit(1);
    }

    if (pcap_set_immediate_mode(p, 1) != 0) {
        pcap_perror(p, "pcap_set_immediate_mode");
        exit(1);
    }

    if (pcap_activate(p) != 0) {
        pcap_perror(p, "pcap_activate");
        exit(1);
    }

    snprintf(filter_string, FILTER_STRING_SIZE, "icmp");

    if (pcap_compile(p, &fcode, filter_string, 0, maskp) == -1) {
        pcap_perror(p, "pcap_compile");
        exit(1);
    }

    if (pcap_setfilter(p, &fcode) == -1) {
        pcap_perror(p, "pcap_setfilter");
        exit(1);
    }
}

int pcap_get_reply(pid_t pid, int seq, const char* data, int timeout_ms) {
    const u_char* packet;
    struct ip* ip_hdr;
    struct icmphdr* icmp_hdr;
    struct timeval start_time, current_time;

    char errbuf[PCAP_ERRBUF_SIZE];

    // set pcap as non-blocking mode to allow timeoout checks
    if (pcap_setnonblock(p, 1, errbuf) == -1) {
        fprintf(stderr, "Error setting pcap to non-blocking mode: %s\n", errbuf);
        return -1;
    }
    // record start time for timeout calculation
    gettimeofday(&start_time, NULL);

    while (1) {
        // calculate elapsed time since the start
        gettimeofday(&current_time, NULL);
        long elapsed_time = (current_time.tv_sec - start_time.tv_sec) * 1000 +
            (current_time.tv_usec - start_time.tv_usec) / 1000;

        if (elapsed_time >= timeout_ms) {
            printf("        Destination unreachable\n");
            pcap_setnonblock(p, 0, errbuf); // back to blocking mode
            return -1; // return timeout error
        }

        // try to capture next packet
        packet = pcap_next(p, &hdr);
        if (packet) {
            ip_hdr = (struct ip*)(packet + 14); // Ethernet header is 14 bytes
            icmp_hdr = (struct icmphdr*)((u_char*)ip_hdr + (ip_hdr->ip_hl * 4));

            // check if the packet is an ICMP reply and matches the expected ID
            if (icmp_hdr->type == ICMP_ECHOREPLY &&
                ntohs(icmp_hdr->un.echo.id) == (pid & 0xFFFF) &&
                ntohs(icmp_hdr->un.echo.sequence) == seq) {

                long reply_time = elapsed_time; // Use the calculated elapsed time directly
                printf("        Reply from %s, time = %ld ms\n", inet_ntoa(ip_hdr->ip_src), reply_time);
                pcap_setnonblock(p, 0, errbuf); // back to blocking mode
                return 0; // receive reply successfully
            }
        }
        //avoid high cpu usage
        usleep(1000); // 1ms
    }
    pcap_setnonblock(p, 0, errbuf);
    return -1;
}







