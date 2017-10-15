#include <stdio.h>
#include <sys/time.h>
#include <netinet/in.h>
#include <pcap/pcap.h>
#include <signal.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include <unistd.h>
#include "expacket.h"
#include <netinet/ip.h>
#include <netinet/tcp.h>
#include <net/ethernet.h>

#define NONPROMISCUOUS 0

struct ip *iph; //ip header struct

struct tcphdr *tcph; //tcp header struct

/*struct tcphdr {

    u_int16_t th_sport;     // source port
    u_int16_t th_dport;     // destination port //

};

struct ip {

#if __BYTE_ORDER == __LITTLE_ENDIAN
    unsigned int ip_hl:4;       // header length //
    unsigned int ip_v:4;        // version //
#endif

#if __BYTE_ORDER == __BIG_ENDIAN
    unsigned int ip_v:4;        // version //
    unsigned int ip_hl:4;       // header length //
#endif
    u_int8_t ip_tos;            // type of service //
    u_short ip_len;         // total length //

#define IP_OFFMASK 0x1fff       // mask for fragmenting bits //
    u_int8_t ip_ttl;            // time to live //
    u_int8_t ip_p;          // protocol //
    u_short ip_sum;         // checksum //
    struct in_addr ip_src, ip_dst;  // source and dest address //

};

// ip, tcp header file => /usr/include/netinet


*/

/*
struct ethhdr
{
    unsigned char   h_dest[ETH_ALEN];   // destination eth addr //
    unsigned char   h_source[ETH_ALEN]; // source ether addr    //
    unsigned short  h_proto;            // packet type ID field //
};

// ethernet header file => /usr/include/linux/if_ether.h

*/

void callback(u_char *useless, const struct pcap_pkthdr *pkthdr,
              const u_char *packet) {

    static int count = 1;
    struct ether_header *ep;
    unsigned short ether_type;
    int chcnt = 0;
    int length = pkthdr->len;

    ep = (struct ether_header *)packet; //bring ethernet header

    packet += sizeof(struct ether_header);
    ether_type = ntohs(ep->ether_type);

    if(ether_type == ETHERTYPE_IP){ //if, ip packet

        iph = (struct ip *)packet;
        printf("IP packet\n");
        printf("Src Address : %s\n", inet_ntoa(iph->ip_src));
        printf("Dst Address : %s\n", inet_ntoa(iph->ip_dst));

        //if, TCP data
        if (iph->ip_p == IPPROTO_TCP) {

            tcph = (struct tcp *)(packet + iph->ip_hl * 4);
            printf("Src Port : %d\n", ntohs(tcph->source));
            printf("Dst Port : %d\n", ntohs(tcph->dest));
        }

        // packet data print

        while(length--) {

            printf("%02x", *(packet++));

            if ((++chcnt % 16) == 0)
                printf("\n");

        }

    }

    // no ip packet

    else {
        printf("None ip packet\n");
    }

    printf("\n\n");

}

int main(int argc, char **argv){

    pcap_t *handle;
    char *dev;
    char *net, mask;
    char errbuf[PCAP_ERRBUF_SIZE]; //error string
    int nwork; //network infomation

    bpf_u_int32 netp, maskp;

    struct pcap_pkthdr hdr;
    struct in_addr net_addr, mask_addr;

    struct bpf_program fp; //the compiled filter

    //define the device
    dev = pcap_lookupdev(errbuf);

    if(dev == NULL) {
        printf("Couldn't find default dev : %s\n",errbuf);
        exit(1);
    }

    printf("dev : %s\n", dev);

    nwork = pcap_lookupnet(dev,&netp,maskp,errbuf);

    if (nwork == -1){
        printf("%s\n",errbuf);
        exit(1);
    }

    net_addr.s_addr = netp;
    net = inet_ntoa(net_addr);
    printf("NET: %s\n",net);

    mask_addr.s_addr = maskp;
    mask = inet_ntoa(mask_addr);
    printf("MASK : %s\n",mask);
    printf("----------------------\n");

    handle = pcap_open_live(dev, BUFSIZ, NONPROMISCUOUS, -1, errbuf);

    if (handle == NULL) {

        printf("%s\n", errbuf);
        exit(1);
    }

    if(pcap_compile(handle, &fp, argv[2],0,netp) == -1){

        printf("compile error\n");
        exit(1);
    }

    if(pcap_setfilter(handle, &fp) == -1) {

        printf("setfilter error\n");
        exit(0);
    }

    pcap_loop(handle, atoi(argv[1]), callback, NULL);

}
