#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <string.h>
#include <sys/ioctl.h>
#include <unistd.h>
#include <errno.h>
#include <getopt.h>
#include <fcntl.h>
#include <sys/socket.h>  
#include <netdb.h>
#include <arpa/inet.h>
#include "sniffer_ioctl.h"

static char * program_name;
static char * dev_file = "sniffer.dev";
static unsigned int cmd;
void usage() 
{
    fprintf(stderr, "Usage: %s [parameters]\n"
                "parameters: \n"
                "    --mode [pass|block]\n"
                "    --direction [in|out]\n"
                "    --interface [XXX|any] : default is any\n"
                "    --proto [tcp|udp|icmp]\n"
                "    --src_ip [url|any] : default is any \n"
                "    --src_port [XXX|any] : default is any \n"
                "    --dst_ip [url|any] : default is any \n" 
                "    --dst_port [XXX|any] : default is any \n"
                "    --action [capture|dpi] : default is null\n", program_name);
    exit(EXIT_FAILURE);
}

int sniffer_send_command(struct sniffer_flow_entry *flow)
{
    printf("interface is %s, source ip:%x; dst_ip:%x; src_port%d; dst_port%d \n",flow->interface,flow->src_ip,flow->dst_ip,flow->src_port,flow->dst_port);
    int fd;
    if((fd = open(flow->dev_file,O_RDWR))<0 )
    {
        perror("Cannot open the device!");
        exit(1);
    }
    if( ioctl(fd,cmd,flow)<0)
        printf("err\n");
    return 0;
}
void init_flow(struct sniffer_flow_entry* flow)
{
    flow->src_ip = 0;
    flow->dst_ip = 0;
    flow->src_port = 0;
    flow -> dst_port = 0;
    flow->action = NONE;
    flow->dev_file = dev_file;
    flow->proto = TCP;
    flow->direction = ALL;
    flow->interface = calloc(10,sizeof(char));
    strcpy(flow->interface ,"ALL");
}
int main(int argc, char **argv)
{
    int c;
    program_name = argv[0];
    struct sniffer_flow_entry* flow = (struct sniffer_flow_entry*)\
    calloc(1,sizeof(struct sniffer_flow_entry));
    init_flow(flow);
    struct hostent *h;
    struct in_addr ** addr_list;
     printf(" argc is %d argv is :%s\n", argc ,*argv);
    while(1) {
        static struct option long_options[] = 
        {
            {"mode", required_argument, 0, 0}, //pass or block
            {"direction", required_argument, 0, 0}, // in or out 
            {"interface", required_argument, 0, 0}, //interface
            {"proto",required_argument,0,0},
            {"src_ip", required_argument, 0, 0},
            {"src_port", required_argument, 0, 0},
            {"dst_ip", required_argument, 0, 0},
            {"dst_port", required_argument, 0, 0},
            {"action", required_argument, 0, 0},
            {"dev", required_argument, 0, 0},
            {0, 0, 0, 0}
        };
        int option_index = 0;
        c = getopt_long (argc, argv, "", long_options, &option_index);
        if (c == -1)
            break;

        switch (c) {
        case 0:
            printf("option %d %s", option_index, long_options[option_index].name);
            if (optarg)
                printf(" with arg %s", optarg);
            printf("\n");

            switch(option_index) {
        //============================================
            case 0:     // mode
            if(strcmp(optarg,"pass")==0)
                cmd = SNIFFER_FLOW_ENABLE;
            else
                cmd = SNIFFER_FLOW_DISABLE;
                break;
        //===========================================
            case 1:    //in or out
             if(strcmp(optarg,"in")==0)
                flow -> direction = IN;
            else if(strcmp(optarg,"out")==0)
            {
                flow -> direction = OUT;
            }
                
            else{
                 usage();
            }   
            break;
        //===========================================
            case 2:     //interface
            if(strlen(optarg)<=9)
                strcpy(flow->interface,optarg);
            printf("strlen :%d\n",strlen(optarg) );
            break;
        //===========================================
            case 3:     //protocol
            if(strcmp(optarg,"tcp")==0){
                flow -> proto = TCP;                
            }
            else if(strcmp(optarg,"udp")==0){
                flow -> proto = UDP;   
            }
            else if(strcmp(optarg,"icmp")==0){
                flow -> proto = ICMP;                
            }
            else 
                usage();
            break;
                
        //===========================================
            case 4:     // src_ip
            if ((h = gethostbyname(optarg)) == NULL) {
              perror("gethostbyname failed \n");
                exit(1);
            }
            addr_list = (struct in_addr **)h->h_addr_list;
            int i = 0;
            for(; addr_list[i] != NULL; i++) {
                 memset(&flow->src_ip,0,sizeof(uint32_t));
                  flow->src_ip = ntohl(addr_list[i]->s_addr);
                //  printf("%x\n",(flow->src_ip));
                break;
            }
                break;
        //============================================
            case 5:     // src_port
             memset(&flow->src_port,0,sizeof(uint16_t));
             flow->src_port = ntohs(atoi(optarg));
                break;
        //==========================================
            case 6:     // dst_ip
            if ((h = gethostbyname(optarg)) == NULL) {
            perror("gethostbyname failed \n");
            exit(1);
            }
            addr_list = (struct in_addr **)h->h_addr_list;
            i = 0;
            for(; addr_list[i] != NULL; i++) {
                memset(&flow->dst_ip,0,sizeof(uint32_t));
                flow->dst_ip = ntohl(addr_list[i]->s_addr);
                break;
            }
            // printf("%x\n",(flow->dst_ip));
                break;
        //==========================================
            case 7:     // dst_port
             memset(&flow->dst_port,0,sizeof(uint16_t));
             flow->dst_port = ntohs(atoi(optarg));
                break;
        //==========================================
            case 8:     // action
            if(strcmp(optarg,"capture")==0)
                flow->action = CAPTURING;
            else if(strcmp(optarg,"DPI")==0)
                flow->action = DPI;
            else 
                {   
                    flow->action = 0;
                    //printf("%s is not a valid mode; please enter valid action mode \n",optarg);
                }
                break;                
        //===========================================
            case 9:     // dev
                flow->dev_file = optarg; 
                break;
            }
            break;
        default:
            usage();
        }
    }
    sniffer_send_command(flow);

    return 0;
}
