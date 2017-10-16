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

#define FILTER_RULE "host 192.168.0.161"
#define PCAP_SNAPSHOT 1024
#define PCAP_TIMEOUT 100

typedef struct mac_address{

    u_char byte1;
    u_char byte2;
    u_char byte3;
    u_char byte4;
    u_char byte5;
    u_char byte6;

}macaddress;


struct ip *iph; //ip header struct
struct tcphdr *tcph; //tcp header struct

void callback(u_char *useless, const struct pcap_pkthdr *pkthdr,
              const u_char *packet) {

    static int count = 1;
    struct ether_header *ep;
    unsigned short ether_type;
    int chcnt = 0;
    int length = pkthdr->len;

    //MAC address save space

    macaddress* Srcmac;
    macaddress* Dstmac;


    //bring ethernet header

    ep = (struct ether_header *)packet;

    //Struct Ethernet header
    //DestinationAddress * SourceAddress * Packet
    // 6 byte 6byte 2byte

    Dstmac=(macaddress*)packet;
    Srcmac=(macaddress*)(packet+6);


    packet += sizeof(struct ether_header);

    ether_type = ntohs(ep->ether_type);

    iph = (struct ip *)packet;

    if(ether_type == ETHERTYPE_IP){

        //if, ip packet


        //if, TCP data


        if (iph->ip_p == IPPROTO_TCP) {

            tcph = (struct tcp *)(packet + iph->ip_hl * 4);


            //struct ip header
            // version * IHL(Header Length) * TOS * Total_length

            //32bitword = 32/8 = 4byte
            //ip_hl = 5 ~15 byte
            //ip_hl * 4byte = ip_header_length
            //packet point = tcp source port

            //print Mac Address

            printf("##############################################\n");

            printf("**Mac Address Session\n");

            printf("Source MAC Address: %02x:%02x:%02x:%02x:%02x:%02x\n",
                   Srcmac->byte1,
                   Srcmac->byte2,
                   Srcmac->byte3,
                   Srcmac->byte4,
                   Srcmac->byte5,
                   Srcmac->byte6	);
            printf("Destinationmac MAC Address: %02x:%02x:%02x:%02x:%02x:%02x\n",
                   Dstmac->byte1,
                   Dstmac->byte2,
                   Dstmac->byte3,
                   Dstmac->byte4,
                   Dstmac->byte5,
                   Dstmac->byte6	);


            //print IP Address

            printf("**IP Address Session\n");

            // inet_ntoa = Big-Endian 32bit -> Dotted-Decimal Notation
            printf("Source IP Address : %s\n", inet_ntoa(iph->ip_src));
            printf("Destination IP Address : %s\n", inet_ntoa(iph->ip_dst));

            //print TCP port

            printf("**TCP Port Session\n");

            printf("Source Tcp port : %d\n", ntohs(tcph->th_sport));
            printf("Destination IP port : %d\n", ntohs(tcph->th_dport));

            printf("##############################################");
            printf("\n\n\n");


        }

        // packet data print

        printf("**PACKET Session\n");

        while(length--) {

            printf("%02x ", *(packet++));

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
    bpf_u_int32 netmask;

    char errbuf[PCAP_ERRBUF_SIZE]; //error string

    struct bpf_program fp; //the compiled filter

    //Preparation

    dev = pcap_lookupdev(errbuf);

    if(dev == NULL) {
        printf("Couldn't find default dev : %s\n",errbuf);
        exit(1);
    }

    printf("dev : %s\n", dev);

    //Open

    handle = pcap_open_live(dev, PCAP_SNAPSHOT, 1 , PCAP_TIMEOUT, errbuf);

    if (handle == NULL) {

        printf("%s\n", errbuf);
        exit(1);
    }

    //Filtering

    if(pcap_compile(handle, &fp, FILTER_RULE,0,netmask) < 0){

        printf("compile error\n");
        exit(1);
    }

    if(pcap_setfilter(handle, &fp) < 0) {

        printf("setfilter error\n");
        exit(1);
    }

    //Read

    if(pcap_loop(handle, -1, callback, 0) < 0) {

       exit(1);
    }

    //close

    pcap_close(handle);

    return 1;

}
