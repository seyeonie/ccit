#ifndef EXPACKET_H
#define EXPACKET_H

#pragma once

#include <sys/time.h>

#pragma pack(1)

#endif // EXPACKET_H

typedef unsigned short ushort;
typedef unsigned char uchar;
typedef unsigned int uint;

/*
#define MAC_ADDR_LEN 6

typedef struct _ethernet{

    unsigned char dest_mac[MAC_ADDR_LEN];
    unsigned char src_mac[MAC_ADDR_LEN];
    unsigned short type;

}ethernet;

typedef struct _iphdr {

    uchar hlen : 4; // header length, 1 per 4 bytes
    ushort tlen; //total length
    uchar protocol;

    uint src_addresss;
    uint dst_address;

}iphdr;
*/
