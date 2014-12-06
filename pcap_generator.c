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
#include <arpa/inet.h>
#include <netdb.h>
#include <pcap/pcap.h>
#include "headers.h"
// #include <linux/inet.h>
// #include <net/ip.h>
// #include <net/tcp.h>
#include <pcap/pcap.h>
static char * program_name;
static char * dev_file = "sniffer.dev";

#define MAX_BUFF_SIZE 65536
#define dumper_filename "OUT.pcap"

void usage() 
{
    fprintf(stderr, "Usage: %s [-i input_file] [-o output_file]\n", program_name);
    exit(EXIT_FAILURE);
}
//the hashtable
HashTable* the_table;
struct list_head rule_head; 
//list of rules 
typedef struct node
{
    struct list_head list;
    int mode; // 0 disable 1 enbale 
    uint32_t src_ip;
    uint32_t dst_ip;
    uint16_t src_port;
    uint16_t dst_port;
    int direction;
    char* interface;
    int action;
    int proto;
}node;

/*
 * entrypoint for the detector
 * 
 * the code provided here only counts packets. modify it as necessary.
 */
 void pack_uint16(uint16_t val, uint8_t* buf) {
    val = htons(val);
    memcpy(buf, &val, sizeof(uint16_t));
 }
uint16_t unpack_uint16(const uint8_t* buf) {
    uint16_t val;
    memcpy(&val, buf, sizeof(uint16_t));
    return ntohs(val);
}
 void pack_uint32(uint32_t val, uint8_t* buf) {
    val = htonl(val);
    memcpy(buf, &val, sizeof(uint32_t));
 }
uint32_t unpack_uint32(const uint8_t* buf) {
    uint32_t val;
    memcpy(&val, buf, sizeof(uint32_t));
    return ntohl(val);
}
/* 
*Hashtable
 */
const int PRIMES[29] = {
   7, 13, 31, 61, 127, 251, 509, 1021, 2039, 4093, 8191, 16381,
   32749, 65521, 131071, 262139, 524287, 1048573, 2097143, 4194301,
   8388593, 16777213, 33554393, 67108859, 134217689, 268435399,
   536870909, 1073741789, 2147483647
};
HashTable* create(int size)
{
    int i =0;
    while(size >PRIMES[i])
        i++;
    size = PRIMES[i];
    HashTable* the_table =malloc(sizeof(HashTable));
    memset(the_table,0,sizeof(HashTable));
    the_table->table = (table_Node **)malloc(size*sizeof(table_Node*));
    memset(the_table->table,0,sizeof(table_Node*));
    i=0;
    for(;i<size;i++)
    {
        the_table->table[i] =NULL;
    }
    the_table->size = size;
    the_table->number_of_pairs = 0;
    return the_table;
}
int size(HashTable* hashtable)
{
    if(hashtable == NULL) return -1;
    return hashtable->size;
}
int isEmpty(HashTable* hashtable) //if empty 0, not empty 1
{
    if(hashtable == NULL) return -1;
    return hashtable->number_of_pairs;
}
int contains(Key* key,HashTable* hashtable)
{
    if(get(key,hashtable)!=NULL)
        return 1;
    return 0;
}
Value* get(Key* key,HashTable* hashtable)
{
    if(hashtable == NULL) return NULL;
    uint32_t hash_v =compute_hash_value(key,hashtable);
    table_Node* node = hashtable->table[hash_v];
    while(node!=NULL)
    {
        if(compare_keys(node->key,key))
            return node->value;
        node = node->next;
    }  
    return NULL;
}
int put(Key* key, Value* value,HashTable* hashtable)
{
    uint32_t hash_v;
    if(hashtable==NULL) return -1;
    hashtable->number_of_pairs++;
    hash_v =compute_hash_value(key,hashtable);
    table_Node* new_node = (table_Node*)malloc(sizeof(table_Node));
    memset(new_node,0,sizeof(table_Node));
    table_Node* temp = hashtable->table[hash_v];
    new_node->value = value;
    new_node->next = temp;
    new_node->key = key;
    hashtable->table[hash_v] = new_node;
    return 0;
}
void delete(Key* key, HashTable* hashtable)
{
    if(hashtable == NULL) return;
    uint32_t hash_v =compute_hash_value(key,hashtable);
    table_Node* node = hashtable->table[hash_v];
    if(node == NULL ) return;
    if(node!=NULL && compare_keys(key,node->key)==1)
    {
        table_Node* temp = node->next;
        free(node->value);
        free(node->key);
        free(node);
        hashtable->table[hash_v] = temp;
        hashtable->number_of_pairs--;
        return;
    }
    table_Node* prev = node;
    table_Node* cur = prev->next;
    while(cur!=NULL)
    {
        if(compare_keys(cur->key, key))
        {
            prev->next = cur->next;
            free(cur->value);
            free(cur->key);
            free(cur);
            hashtable->number_of_pairs--;
            return;
        }
        prev = cur;
        cur = cur->next;
    }
}
uint32_t compute_hash_value(Key* key, HashTable* hashtable)
{
    uint32_t ports = key->src_port ^ key->dst_port;
    return (ports^(key->src_ip^key->dst_ip))%hashtable->size;
}
int compare_keys(Key* this, Key* other)
{
    if( this->proto == other->proto &&this->src_port == other->src_port && this->dst_port == other->dst_port && this->dst_ip == other->dst_ip && this->src_ip == other->src_ip)
      {
        return 1;   
      }  
    return 0;    
}
void free_table(HashTable* hashtable)
{
    if(hashtable==NULL) return;
    int i=0;
    for(;i<hashtable->size;i++)
    {
        table_Node* node = hashtable->table[i];
        table_Node* temp;
        while(node!=NULL)
        {
            temp = node;
            node = node->next;
            free(temp->value);
            free(temp->key);
            free(temp);
        }
    }   
    free(hashtable->table);;
    free(hashtable);
}
//----------------------------------------
static inline struct tcphdr * ip_tcp_hdr(struct iphdr *iph)
{
    struct tcphdr *tcph = (void *) iph + iph->ihl*4;
    return tcph;
}
static inline struct udphdr * ip_udp_hdr(struct iphdr *iph)
{
    struct udphdr *udph = (void *) iph + iph->ihl*4;
    return udph;
}
static int firewall(struct iphdr *iph)
{ 
    node* pos;
    Key* key = malloc(sizeof(Key));
    memset(key,0,sizeof(Key));
    if (iph->protocol == IPPROTO_TCP) {
        struct tcphdr *tcph = ip_tcp_hdr(iph);
        key->src_ip = ntohl(iph->saddr);
        key->dst_ip = ntohl(iph->daddr);
        key->src_port = tcph->source;
        key->dst_port = tcph->dest;
        key->proto = TCP;
        uint8_t flag = *((uint8_t*)tcph+13);
        printf( "TCP from :%x: to :%x src_port:%d dst_port:%d flag:%d \n",iph->saddr,iph->daddr,tcph->source,tcph->dest,flag);
        if(contains(key,the_table)==1)
        {
            Value* value = get(key,the_table);
            if(flag&RST)
            {
                delete(key,the_table);
                return 1;
            }
            else if(value->state == HALFOPEN && (flag & SYN) && !(flag & ACK)) //retransmitting SYN 
            {
                printf( "ACCEPT(retransmitting SYN) HALFOPEN--from Hashtable\n ");
                return 1;
            } 
            else if(value->state == CONNECTED && !(flag & SYN) && (flag & ACK) && !(flag & FIN)) 
            {
                printf( "ACCEPT (Transmittin Data) CONNECTED --from Hashtable\n ");
                return 1;
            }
            else if(value->state == CONNECTED && (flag & ACK) && (flag & FIN)) //received FIN
            {
                value->state = CLOSING;
                value->FIN_direction =F_dst;
                printf( "ACCEPT (FIN from dst_ip) CLOSING--from Hashtable\n ");
                return 1;
            }
            else if(value->state == CLOSING && (flag & ACK) && (flag & FIN) && value->FIN_direction == F_src) //received FIN allow FIN/ACK and ACK
            {
                delete(key,the_table);
                printf( "ACCEPT (FIN from dst_ip) CLOSED --from Hashtable\n ");
                return 1;
            } 
            else if(value->state == CLOSING &&  (flag & ACK) && !(flag & FIN)) //allow ack to go out
            {
                printf( "ACCEPT (ACK from dst_ip) CLOSING --from Hashtable\n ");
                return 1;
            }
            else
            {
                printf( "DROP state is:%d, flag is:%d--from Hashtable\n ",value->state,flag);
                return 0;
            }
        } 
        //counterpart
        key->src_ip = ntohl(iph->daddr);
        key->dst_ip = ntohl(iph->saddr);
        key->src_port = tcph->dest;
        key->dst_port = tcph->source;
        if(contains(key,the_table)==1)
        {
            Value* value = get(key,the_table);
            if(flag&RST)
            {
                delete(key,the_table);
                return 1;
            }
            else if(value->state == HALFOPEN && (flag & (SYN|ACK))) //Sending back SYN/ACK 
            {
                value->state = CONNECTED;
                printf( "ACCEPT( SENDING SYN/ACK) HALFOPEN--from Hashtable\n ");

                return 1;
            } 
            else if(value->state == CONNECTED && !(flag & SYN) && (flag & ACK) && !(flag & FIN)) 
            {
                printf( "ACCEPT (Transmittin Data) CONNECTED --from Hashtable\n ");

                return 1;
            }
            else if(value->state == CONNECTED && (flag & ACK) && (flag & FIN)) //received FIN
            {
                value->state = CLOSING;
                value->FIN_direction =F_src;
                printf( "ACCEPT (FIN from src_ip) CLOSING--from Hashtable\n ");

                return 1;
            }
            else if(value->state == CLOSING && (flag & ACK) && (flag & FIN) && value->FIN_direction == F_dst) //received FIN
            {
                delete(key,the_table);
                printf( "ACCEPT (FIN from src_ip) CLOSED --from Hashtable\n ");

                return 1;
            }
            else if(value->state == CLOSING &&  (flag & ACK) && !(flag & FIN)) //allow ack to go out
            {
                printf( "ACCEPT (ACK from src_ip) CLOSING --from Hashtable\n ");

                return 1;
            }
            else
            {
                printf( "DROP state is:%d, flag is:%d--from Hashtable\n ",value->state,flag);
                return 0;
            }
        } 
        list_for_each_entry(pos,&rule_head,list)
        {
            if( (pos->src_ip == ntohl(iph->saddr) || pos->src_ip == 0)\
                && (pos->dst_ip == ntohl(iph->daddr) || pos->dst_ip == 0)\
                && (pos->src_port == tcph->source || pos->src_port == 0)\
                && (pos->dst_port == tcph->dest || pos->dst_port == 0) \
                && (pos->proto == TCP) )
            {
                if(pos->mode == 0){
                    printf("TCP_DROP(Blocked by rule) -- from list\n");
                    return 0;
                }
                if(flag&SYN && !(flag&ACK)){
                    Value* v = malloc(sizeof(Value));
                    memset(v,0,sizeof(Value));
                    v->proto =TCP;
                    v->state = HALFOPEN; 
                    key->src_ip = ntohl(iph->saddr);
                    key->dst_ip = ntohl(iph->daddr);
                    key->src_port = tcph->source;
                    key->dst_port = tcph->dest;
                    put(key,v,the_table);
                    printf("TCP_ACCEPT -- from list");
        
                    return 1; 
                }else{
                    printf("TCP_DROP(flag is not SYN) -- from list\n");
                    return 0;
                }
            }
        }
        printf("TCP_DROP -- from list (no such rule)\n");
        return 0;
    }
    free(key);
    if( iph->protocol == IPPROTO_ICMP)
    {
        Key* key = malloc(sizeof(Key));
        memset(key,0,sizeof(Key));
        key->src_ip = ntohl(iph->saddr);
        key->dst_ip = ntohl(iph->daddr);
        key->src_port = 0;
        key->dst_port = 0;
        key->proto = ICMP;
        if(contains(key,the_table)==1)
        {
            Value* v = get(key,the_table);
            printf( "ICMP ---Hashtable\n");
            free(key);
           return 1;
        } 

         list_for_each_entry(pos,&rule_head,list)
        {
            if( (pos->src_ip == ntohl(iph->saddr) || pos->src_ip == 0)\
                && (pos->dst_ip == ntohl(iph->daddr) || pos->dst_ip == 0)\
                && (pos->proto == ICMP))
            {
                if(pos->mode == 0)
                {
                    free(key);
                    return 0;
                }
                Value* v = malloc(sizeof(Value));
                memset(v,0,sizeof(Value));
                v->proto =ICMP;
                put(key,v,the_table);

                return 1; 
            }
        }
        return 0;
    }
    if(iph->protocol == IPPROTO_UDP)
    {
        struct udphdr *udp_h = ip_udp_hdr(iph);
        Key* key = malloc(sizeof(Key));
        memset(key,0,sizeof(Key));
        key->src_ip = ntohl(iph->saddr);
        key->dst_ip = ntohl(iph->daddr);
        key->src_port = udp_h->source;
        key->dst_port = udp_h->dest;
        key->proto = UDP;
        //key->direction = direction;
        // key->interface = malloc(10*sizeof(char));
        //memset(key->interface,0,10*sizeof(char));
        //strcpy(key->interface,dev->name);
        if(contains(key,the_table)==1)
        {
            // Value* v = get(key,the_table);
            // if(v->direction != direction )
            // {
            //     printf( "UDP --0\n");
            //     return 0;
            // }
            printf( "UDP ---Hashtable\n");
            free(key);
           return 1;
        } 
        list_for_each_entry(pos,&rule_head,list)
        {
            if( (pos->src_ip == ntohl(iph->saddr) || pos->src_ip == 0)\
                && (pos->dst_ip == ntohl(iph->daddr) || pos->dst_ip == 0)\
                && (pos->src_port == udp_h->source || pos->src_port == 0)\
                && (pos->dst_port == udp_h->dest || pos->dst_port == 0) \
                && (pos->proto == UDP))
                //&& (pos->direction == direction || pos->direction == ALL)\
                //&& ((strncmp(pos->interface,dev->name,IFNAMSIZ)==0) || (strcmp(pos->interface,"ALL")==0)) )
            {
                 if(pos->mode == 0)
                {
                    free(key);
                    return 0;
                }
                Value* v = malloc(sizeof(Value));
                memset(v,0,sizeof(Value));
                v->proto =UDP;
                //v->direction = direction;
                put(key,v,the_table);
                    return 1; 
            }
        }
        return 0;
    }
    return 1;
}


static void add_rule(unsigned int cmd, struct sniffer_flow_entry * arg)
{
    node* new_node = malloc(sizeof(node));
    struct sniffer_flow_entry * converted_arg;


    converted_arg = (struct sniffer_flow_entry *)arg;

        new_node->src_ip = converted_arg->src_ip;
        new_node->dst_ip = converted_arg->dst_ip;
        new_node->src_port = converted_arg->src_port;
        new_node->dst_port = converted_arg->dst_port;
        new_node->action = converted_arg->action;
        new_node->direction = converted_arg->direction;
        new_node->interface = malloc(10*sizeof(char));
        memset(new_node->interface,0,10*sizeof(char));
        strcpy(new_node->interface,converted_arg->interface);
        if(new_node->interface)
            printf( "INTERFACE:%s", new_node->interface);
        new_node->proto = converted_arg->proto;
        //check if a new rule is UDP or ICMP && disallow;
        if((new_node->proto==UDP || new_node->proto == ICMP)&& cmd == SNIFFER_FLOW_DISABLE)
        {
            Key* key = malloc(sizeof(Key));
            memset(key,0,sizeof(Key));
            key->src_ip = new_node->src_ip;
            key->dst_ip = new_node->dst_ip;
            key->src_port = new_node->src_port;
            key->dst_port = new_node->dst_port;
            key->proto = new_node->proto;
            if(key->proto == ICMP)
            {  
                key->src_port = 0;
                key->dst_port = 0;
            }
            delete(key,the_table);
            free(key);
        }

    switch(cmd) {
    case SNIFFER_FLOW_ENABLE:
        new_node->mode =1;
        list_add(&new_node->list,&rule_head);
        break;

    case SNIFFER_FLOW_DISABLE:
        new_node->mode =0;
        list_add(&new_node->list,&rule_head);
        break;
    default:
        free(new_node);
        printf( "Unknown command\n");
    }

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
      INIT_LIST_HEAD(&rule_head);
    int result;
    static unsigned int cmd;
    struct hostent *h;
    struct in_addr ** addr_list;
    FILE* rule_f = fopen("rules.txt","r");
    char line[256];
    while (fgets(line, sizeof(line), rule_f)) {
        struct sniffer_flow_entry* flow = (struct sniffer_flow_entry*)\
        calloc(1,sizeof(struct sniffer_flow_entry));
        init_flow(flow);
         printf("%s\n", line);
         
        char* p = strtok(line,",");
        if(strcmp(p,"pass")==0)
            cmd = SNIFFER_FLOW_ENABLE;
        else
            cmd = SNIFFER_FLOW_DISABLE;
         printf("%s\n",p);
        p = strtok(NULL,",");
        if(strcmp(p,"in")==0)
                flow -> direction = IN;
        else if(strcmp(p,"out"))
        {
            flow -> direction = OUT;
        }
        printf("%s\n",p);
        p = strtok(NULL,",");
        if(strlen(p)<=9)
                strcpy(flow->interface,p);
        printf("%s\n",p);
        p = strtok(NULL,",");
        if(strcmp(p,"tcp")==0){
                flow -> proto = TCP;                
            }
            else if(strcmp(p,"udp")==0){
                flow -> proto = UDP;   
            }
            else{
                flow -> proto = ICMP;                
            }
        printf("%s\n",p);
        p = strtok(NULL,",");
        if ((h = gethostbyname(p)) == NULL) {
          perror("gethostbyname failed \n");
            exit(1);
        }
        addr_list = (struct in_addr **)h->h_addr_list;
        int i = 0;
        for(; addr_list[i] != NULL; i++) {
             memset(&flow->src_ip,0,sizeof(uint32_t));
              flow->src_ip = ntohl(addr_list[i]->s_addr);
              break;
        }
        printf("%s\n",p);
        p = strtok(NULL,",");
         memset(&flow->src_port,0,sizeof(uint16_t));
             flow->src_port = ntohs(atoi(p));

        printf("%s\n",p);
        p = strtok(NULL,",");
        if ((h = gethostbyname(p)) == NULL) {
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
        printf("%s\n",p);
         p = strtok(NULL,",");
         memset(&flow->dst_port,0,sizeof(uint16_t));
             flow->dst_port = ntohs(atoi(p));
        printf("%s\n",p );
        add_rule(cmd,flow);
        //init_flow(flow);
    }
    fclose(rule_f);

   
    // cmd =SNIFFER_FLOW_ENABLE;
    // add_rule(cmd,flow);
    const ethernet_hdr_t* e_header =NULL;
    const uint8_t* packet = NULL;
    struct pcap_pkthdr* header = NULL;
    program_name = argv[0];

    char errbuf[PCAP_ERRBUF_SIZE];
    pcap_t* dumper_handle = pcap_open_dead(DLT_EN10MB, 65535);
     if (dumper_handle == NULL)
    {
    printf("dumper handle error: %s\n", errbuf);
    return 1;
    }
    pcap_t* handle = pcap_open_offline(argv[1], errbuf);
    if (handle == NULL) {
        printf("error: %s\n", errbuf);
        return 1;
    }
    pcap_dumper_t * dumper = pcap_dump_open(dumper_handle, dumper_filename);
    if (dumper == NULL)
    {
    printf("dumper_t error\n");
    return 1;
    }  
    while(1) {
        result = pcap_next_ex(handle, &header, &packet);
        if (result == -2) break;
        else if (result == -1)
        perror("pcap read error!");
        else
        {
            e_header = (const ethernet_hdr_t*)packet;
            if(unpack_uint16(e_header->ethertype)==IPV4)
            {
                struct iphdr* ipd = (const struct iphdr*) e_header->data;
                if(firewall(ipd) ==1)
                    pcap_dump((u_char*)dumper, header,(const u_char*)packet);
            }
        }
    }
    pcap_dump_close(dumper);
    pcap_close(dumper_handle);
    return 0;
}
