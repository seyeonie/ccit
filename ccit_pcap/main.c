#include <stdio.h>
#include <sys/time.h>
#include <netinet/in.h>
#include <pcap/pcap.h>
#include <signal.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include <unistd.h>
#include <netinet/ip.h>
#include <netinet/tcp.h>
#include <net/ethernet.h>
#include <sys/socket.h>
#include <arpa/inet.h>

#define FILTER_RULE "host 192.168.0.12"
#define PCAP_SNAPSHOT 1024
#define PCAP_TIMEOUT 100

struct ip *iph; //ip header struct

struct tcphdr *tcph; //tcp header struct

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
    bpf_u_int32 netp;

    char errbuf[PCAP_ERRBUF_SIZE]; //error string

    struct bpf_program fp; //the compiled filter

    //define the device

    dev = pcap_lookupdev(errbuf);

    if(dev == NULL) {
        printf("Couldn't find default dev : %s\n",errbuf);
        exit(1);
    }

    printf("dev : %s\n", dev);

    handle = pcap_open_live(dev, PCAP_SNAPSHOT, 1 , PCAP_TIMEOUT, errbuf);

    if (handle == NULL) {

        printf("%s\n", errbuf);
        exit(1);
    }

    if(pcap_compile(handle, &fp, FILTER_RULE,0,netp) == -1){

        printf("compile error\n");
        exit(1);
    }

    if(pcap_setfilter(handle, &fp) == -1) {

        printf("setfilter error\n");
        exit(1);
    }

    if(pcap_loop(handle, -1, callback, NULL) == -1) {

       exit(1);
    }

    pcap_close(handle);
    return 1;

}
