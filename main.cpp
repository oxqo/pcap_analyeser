#include <sys/time.h>
#include <netinet/in.h>
#include <net/ethernet.h>
#include <pcap/pcap.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include <unistd.h>
#include <arpa/inet.h>
#include <netinet/ether.h>
#include <netinet/ip.h>
#include <netinet/tcp.h>
#include <netinet/udp.h>
#include <netinet/ip_icmp.h>

#define PROMISCUOUS 1
#define NONPROMISCUOUS 0

struct ip *iph;
struct tcphdr *tcph;

void callback(u_char *useless, const struct pcap_pkthdr *pkthdr,
                const u_char *packet)
{
    struct ether_header *ep;
    unsigned short ether_type;
    int chcnt =0;
    int length=pkthdr->len;
    const u_char *p_tmp;

    ep = (struct ether_header *)packet;

    printf("dmac: ");
    for(int j=0; j<6; j++){
        printf("%02X", *(ep->ether_dhost+j));
        if(j != 5)
            printf(" : ");
        else
            printf("\n");
    }


    printf("smac: ");
    for(int j=0; j<6; j++){
        printf("%02X", *(ep->ether_shost+j));
        if(j != 5)
            printf(" : ");
        else
            printf("\n");
    }


    p_tmp = packet;
    packet += sizeof(struct ether_header);


    ether_type = ntohs(ep->ether_type);



    if (ether_type == ETHERTYPE_IP)
    {
        iph = (struct ip *)packet;
        printf("Src Address : %s\n", inet_ntoa(iph->ip_src));
        printf("Dst Address : %s\n", inet_ntoa(iph->ip_dst));

        if (iph->ip_p == IPPROTO_TCP)
        {
            tcph = (struct tcphdr *)(packet + iph->ip_hl * 4);
            printf("Src Port : %d\n" , ntohs(tcph->source));
            printf("Dst Port : %d\n" , ntohs(tcph->dest));
        }

        printf("\n");

        for(int i=0; i<16; i++ ){
            printf("%c[31m%02X ", 27, i);
        }

        printf("\n");
        printf("%c[0m", 0x1b);
        packet = p_tmp;
        while(length--)
        {
            printf("%02x ", *(packet++));
            if ((++chcnt % 16) == 0)
                printf("\n");
        }
        printf("\n\n=============================================");
    }

    else
    {
        printf("NONE IP 패킷\n");
    }

    printf("\n\n");
}

int main(int argc, char **argv)
{
    char *dev;
    bpf_u_int32 netp;
    bpf_u_int32 maskp;
    char errbuf[PCAP_ERRBUF_SIZE];
    int ret;
    struct bpf_program fp;

    pcap_t *pcd;

    if(argc != 4){
        printf("usage: ./pcap_analyser loop_count filter_rule device\n");
        exit(1);
    }


    dev = argv[3];
    printf("DEV : %s\n", dev);

    ret = pcap_lookupnet(dev, &netp, &maskp, errbuf);
    if (ret == -1)
    {
        printf("%s\n", errbuf);
        exit(1);
    }


    pcd = pcap_open_live(dev, BUFSIZ,  NONPROMISCUOUS, -1, errbuf);
    if (pcd == NULL)
    {
        printf("%s\n", errbuf);
        exit(1);
    }

    if (pcap_compile(pcd, &fp, argv[2], 0, netp) == -1)
    {
        printf("compile error\n");
        exit(1);
    }

    if (pcap_setfilter(pcd, &fp) == -1)
    {
        printf("setfilter error\n");
        exit(0);
    }

    pcap_loop(pcd, atoi(argv[1]), callback, NULL);

}
