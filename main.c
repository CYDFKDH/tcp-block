#include <pcap.h>
#include <stdio.h>
#include <errno.h>
#include <stdint.h>
#include <stdlib.h>
#include <unistd.h>
#include <string.h>
#include <signal.h>
#include <net/if.h>
#include <stdbool.h>
#include <sys/types.h>
#include <sys/ioctl.h>
#include <arpa/inet.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <netinet/ether.h>
#include <linux/if_packet.h>
#include <netinet/ip.h>
#include <netinet/tcp.h>

#define MAC_LEN 6

typedef struct {
    uint8_t dstMac[MAC_LEN];
    uint8_t srcMac[MAC_LEN];
    uint16_t ethType;
} EthernetHeader;

typedef struct {
    EthernetHeader *eth;
    struct ip *ip;
    struct tcphdr *tcp;
    char *data;
} Packet;

typedef struct {
    uint32_t srcAddr;
    uint32_t dstAddr;
    uint8_t reserved;
    uint8_t protocol;
    uint16_t tcpLen;
} PseudoHeader;

int get_mac_address(uint8_t *mac, const char *dev) {
    int sock;
    struct ifreq ifr;

    sock = socket(AF_INET, SOCK_STREAM, 0);
    if (sock < 0) {
        perror("socket");
        return -1;
    }

    strncpy(ifr.ifr_name, dev, IFNAMSIZ - 1);
    if (ioctl(sock, SIOCGIFHWADDR, &ifr) < 0) {
        perror("ioctl");
        close(sock);
        return -1;
    }

    memcpy(mac, ifr.ifr_hwaddr.sa_data, MAC_LEN);

    close(sock);
    return 0;
}

void print_usage() {
    printf("Usage: tcp-block <interface> <pattern>\n");
    printf("Example: tcp-block wlan0 \"Host: test.gilgil.net\"\n");
}

uint16_t parse_packet(Packet *pkt, const u_char *packet) {
    uint16_t header_len = 0;

    pkt->eth = (EthernetHeader *)packet;
    header_len += sizeof(EthernetHeader);

    pkt->ip = (struct ip *)((uint8_t *)(pkt->eth) + header_len);
    header_len += pkt->ip->ip_hl << 2;

    pkt->tcp = (struct tcphdr *)((uint8_t *)(pkt->eth) + header_len);
    header_len += pkt->tcp->doff << 2;

    pkt->data = (char *)((uint8_t *)(pkt->eth) + header_len);
    return header_len;
}

uint16_t calculate_checksum(uint16_t *data, int len) {
    uint32_t checksum = 0;
    for (int i = 0; i < len / 2; i++) {
        checksum += ntohs(data[i]);
        if (checksum > 0xFFFF) {
            checksum %= 0x10000;
            checksum += 1;
        }
    }
    return (uint16_t)checksum;
}

void update_checksums(Packet *pkt, uint16_t tcp_len) {
    PseudoHeader pseudo_hdr;
    pseudo_hdr.srcAddr = pkt->ip->ip_src.s_addr;
    pseudo_hdr.dstAddr = pkt->ip->ip_dst.s_addr;
    pseudo_hdr.reserved = 0;
    pseudo_hdr.protocol = pkt->ip->ip_p;
    pseudo_hdr.tcpLen = htons(tcp_len);

    pkt->ip->ip_sum = 0;
    pkt->tcp->check = 0;

    pkt->ip->ip_sum = htons(calculate_checksum((uint16_t *)pkt->ip, sizeof(struct ip)) ^ 0xFFFF);

    uint32_t temp = calculate_checksum((uint16_t *)&pseudo_hdr, sizeof(PseudoHeader)) +
                    calculate_checksum((uint16_t *)pkt->tcp, tcp_len + 1);
    temp = (temp > 0xFFFF) ? (temp % 0x10000) + 1 : temp;
    pkt->tcp->check = htons((uint16_t)temp ^ 0xFFFF);
}

int main(int argc, char *argv[]) {
    const char *redirect = "HTTP/1.0 302 Redirect\r\nLocation: http://warning.or.kr\r\n\r\n";
    char pattern[1024];

    if (argc != 3) {
        print_usage();
        return EXIT_FAILURE;
    }

    char *interface = argv[1];
    strncpy(pattern, argv[2], sizeof(pattern) - 1);
    pattern[sizeof(pattern) - 1] = '\0';

    Packet org_pkt, fwd_pkt, bkwd_pkt;
    uint8_t fwd_packet[200];
    uint8_t bkwd_packet[200];
    uint8_t my_mac[MAC_LEN];
    uint16_t header_len, data_len, packet_len;

    if (get_mac_address(my_mac, interface) < 0) {
        return EXIT_FAILURE;
    }

    int fd = socket(PF_PACKET, SOCK_RAW, IPPROTO_RAW);
    if (fd < 0) {
        perror("socket");
        return EXIT_FAILURE;
    }

    struct sockaddr_ll dest = {0};
    dest.sll_family = PF_PACKET;
    dest.sll_protocol = htons(ETH_P_IP);
    dest.sll_ifindex = if_nametoindex(interface);

    char errbuf[PCAP_ERRBUF_SIZE];
    pcap_t *pcap = pcap_open_live(interface, BUFSIZ, 1, 1, errbuf);
    if (pcap == NULL) {
        fprintf(stderr, "pcap_open_live(%s) returned NULL - %s\n", interface, errbuf);
        return EXIT_FAILURE;
    }

    while (true) {
        struct pcap_pkthdr *header;
        const u_char *packet;
        int res = pcap_next_ex(pcap, &header, &packet);
        if (res == 0) continue;
        if (res == PCAP_ERROR || res == PCAP_ERROR_BREAK) {
            fprintf(stderr, "pcap_next_ex returned %d(%s)\n", res, pcap_geterr(pcap));
            break;
        }

        header_len = parse_packet(&org_pkt, packet);

        if (ntohs(org_pkt.eth->ethType) == ETHERTYPE_IP && org_pkt.ip->ip_v == IPVERSION && org_pkt.ip->ip_p == IPPROTO_TCP) {
            packet_len = sizeof(EthernetHeader) + sizeof(struct ip) + sizeof(struct tcphdr);
            data_len = ntohs(org_pkt.ip->ip_len) - (header_len - sizeof(EthernetHeader));
            org_pkt.data[data_len] = '\0';

            bool found_pattern = false;
            int pattern_len = strlen(pattern);
            int search_len = data_len - pattern_len;
            for (int i = 0; i <= search_len; i++) {
                if (memcmp(org_pkt.data + i, pattern, pattern_len) == 0) {
                    found_pattern = true;
                    break;
                }
            }

            if (!found_pattern) continue;

            printf("Pattern found!\n");

            memcpy(fwd_packet, packet, packet_len);
            memcpy(bkwd_packet, packet, packet_len);

            parse_packet(&fwd_pkt, fwd_packet);
            parse_packet(&bkwd_pkt, bkwd_packet);

            memcpy(fwd_pkt.eth->srcMac, my_mac, MAC_LEN);
            memcpy(bkwd_pkt.eth->srcMac, my_mac, MAC_LEN);
            memcpy(bkwd_pkt.eth->dstMac, org_pkt.eth->srcMac, MAC_LEN);

            fwd_pkt.ip->ip_len = htons(sizeof(struct ip) + sizeof(struct tcphdr));
            bkwd_pkt.ip->ip_len = htons(sizeof(struct ip) + sizeof(struct tcphdr) + strlen(redirect));

            bkwd_pkt.ip->ip_ttl = 128;

            bkwd_pkt.ip->ip_src.s_addr = org_pkt.ip->ip_dst.s_addr;
            bkwd_pkt.ip->ip_dst.s_addr = org_pkt.ip->ip_src.s_addr;

            fwd_pkt.tcp->urg_ptr = 0;
            bkwd_pkt.tcp->urg_ptr = 0;

            bkwd_pkt.tcp->source = org_pkt.tcp->dest;
            bkwd_pkt.tcp->dest = org_pkt.tcp->source;

            fwd_pkt.tcp->seq = htonl(ntohl(org_pkt.tcp->seq) + data_len);
            bkwd_pkt.tcp->seq = htonl(ntohl(org_pkt.tcp->ack_seq));
            bkwd_pkt.tcp->ack_seq = htonl(ntohl(org_pkt.tcp->seq) + data_len);

            fwd_pkt.tcp->doff = sizeof(struct tcphdr) / 4;
            bkwd_pkt.tcp->doff = sizeof(struct tcphdr) / 4;

            fwd_pkt.tcp->rst = 1;
            fwd_pkt.tcp->ack = 1;

            bkwd_pkt.tcp->fin = 1;
            bkwd_pkt.tcp->rst = 0;
            bkwd_pkt.tcp->ack = 1;

            memcpy(bkwd_packet + packet_len, redirect, strlen(redirect));
            bkwd_pkt.data = (char *)(bkwd_packet + packet_len);
            bkwd_pkt.data[strlen(redirect)] = 0;

            update_checksums(&fwd_pkt, sizeof(struct tcphdr));
            update_checksums(&bkwd_pkt, sizeof(struct tcphdr) + strlen(redirect));

            memcpy(dest.sll_addr, fwd_pkt.eth->dstMac, MAC_LEN);
            if (sendto(fd, fwd_packet, packet_len, 0, (struct sockaddr *)&dest, sizeof(dest)) <= 0) perror("forward");

            memcpy(dest.sll_addr, bkwd_pkt.eth->dstMac, MAC_LEN);
            if (sendto(fd, bkwd_packet, packet_len + strlen(redirect), 0, (struct sockaddr *)&dest, sizeof(dest)) <= 0) perror("backward");
        }
    }

    pcap_close(pcap);
    return EXIT_SUCCESS;
}

