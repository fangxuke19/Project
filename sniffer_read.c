#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <string.h>
#include <sys/ioctl.h>
#include <unistd.h>
#include <getopt.h>
#include "sniffer_ioctl.h"
#include <fcntl.h>
#include "list.h"

#include <linux/cdev.h>
#include <linux/types.h>
#include <linux/init.h>
#include <linux/kernel.h>
#include <linux/moduleparam.h>
#include <linux/version.h>
#include <linux/netdevice.h>
#include <linux/netfilter_ipv4.h>
#include <linux/inet.h>
#include <linux/mm.h>
#include <linux/udp.h>
#include <linux/fs.h>
#include <arpa/inet.h>
#include <pcap/pcap.h>
static char * program_name;
static char * dev_file = "sniffer.dev";

#define MAX_BUFF_SIZE 65536
#define dumper_filename "OUT.pcap"
uint32_t unpack_uint32(const uint8_t* buf) {
    uint32_t val;
    memcpy(&val, buf, sizeof(uint32_t));
    return val;
   // return ntohl(val);
}
uint16_t unpack_uint16(const uint8_t* buf) {
    uint16_t val;
    memcpy(&val, buf, sizeof(uint16_t));
    return ntohs(val);
}

void usage() 
{
    fprintf(stderr, "Usage: %s [-i input_file] [-o output_file]\n", program_name);
    exit(EXIT_FAILURE);
}

int print_packet(char * pkt, int len)
{
    int i=0;
     ip_hdr_t* ip_h = (ip_hdr_t *) pkt;
     tcp_hdr_t* tcp_h = (tcp_hdr_t *) ip_h->options_and_data;
      uint32_t src_ip = ip_h->src_ip;
      uint32_t dst_ip = ip_h->dst_ip;
    uint16_t src_port = unpack_uint16(tcp_h->src_port);
    uint16_t dst_port = unpack_uint16(tcp_h->dst_port);
    struct in_addr src_ip_addr;
    src_ip_addr.s_addr = src_ip;
     struct in_addr dst_ip_addr;
    dst_ip_addr.s_addr = dst_ip;

    printf("%s:%d ->",inet_ntoa(src_ip_addr),src_port);
    printf("%s:%d\n" ,inet_ntoa(dst_ip_addr),dst_port);
    for(;i<len;i++)
    {
        if(i%64 == 0 && i>0)
            printf("\n");
        printf("%.2x ",(unsigned char)pkt[i]);
            
    }
    printf("\n");
    return 0;
}
int main(int argc, char **argv)
{
    int c;
    char *input_file, *output_file = NULL;
    program_name = argv[0];

    input_file= dev_file;

    while((c = getopt(argc, argv, "i:o:")) != -1) {
        switch (c) {
        case 'i':
            input_file = argv[0];
            break;
        case 'o':
            output_file = argv[1];
            break;
        default:
            usage();
        }
    }
    int fd; 
    if((fd =open(input_file,O_RDONLY))<0)
    {
        printf("cannot open the file%s",dev_file);
        exit(1);
    }
    char* buf = malloc(MAX_BUFF_SIZE);
	  int count =0;  
    
    char errbuf[PCAP_ERRBUF_SIZE];
    struct pcap_pkthdr* header = NULL;
    pcap_t* dumper_handle = pcap_open_dead(DLT_EN10MB, 65535);
     if (dumper_handle == NULL)
    {
    printf("dumper handle error: %s\n", errbuf);
    return 1;
    }
    pcap_dumper_t * dumper = pcap_dump_open(dumper_handle, dumper_filename);
    if (dumper == NULL)
    {
    printf("dumper_t error\n");
    return 1;
    }  
    if(output_file)
        if(freopen(output_file,"w",stdout))
        {
            printf("cannot open the file%s",output_file);
            exit(1);
        }
    while((count=read(fd,buf,MAX_BUFF_SIZE))>0)
    {
        print_packet(buf,count);
        pcap_dump((u_char*)dumper, header, (const u_char*)buf);
    }
    pcap_dump_close(dumper);
    pcap_close(dumper_handle);


    free(buf);

    return 0;
}
