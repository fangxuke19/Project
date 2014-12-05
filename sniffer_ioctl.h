#ifndef __SNIFFER_IOCTL_
#define __SNIFFER_IOCTL__

struct sniffer_flow_entry {
    uint32_t src_ip;
  	uint32_t dst_ip;
  	uint16_t src_port;
  	uint16_t dst_port;
    int direction;
    #define IN -1
    #define OUT -2
    #define ALL 0
    char* interface;
  	int action;
    int proto;
    #define TCP -3
    #define UDP -4
    #define ICMP -5
  	char* dev_file;	
};


#define SNIFFER_IOC_MAGIC       'p'

#define SNIFFER_FLOW_ENABLE     _IOW(SNIFFER_IOC_MAGIC, 0x1, struct sniffer_flow_entry)
#define SNIFFER_FLOW_DISABLE    _IOW(SNIFFER_IOC_MAGIC, 0x2, struct sniffer_flow_entry)

#define SNIFFER_IOC_MAXNR   0x3


#define SNIFFER_ACTION_NULL     0x0
#define SNIFFER_ACTION_CAPTURE  0x1
#define SNIFFER_ACTION_DPI      0x2
//ACTIONS
#define NONE 0
#define CAPTURING 1
#define DPI 2
//DPI Pattern 
#define PATTERN "You got it!"

#endif /* __SNIFFER_IOCTL__ */
/*
  *struct for ip header
  */
 typedef struct {
  uint8_t version_ihl;
  uint8_t dscp_ecn;  
  uint8_t total_len[2];
  uint8_t identification[2];
  uint8_t flags_frag[2];
  uint8_t time_to_live;
  uint8_t protocol;
  uint8_t checksum[2];
  uint32_t src_ip;
  uint32_t dst_ip;
  uint8_t options_and_data[0];
} ip_hdr_t;
/*
 *struct for the tcp header
 */
typedef struct    
{
  uint8_t src_port[2];
  uint8_t dst_port[2];
  uint8_t seq_num[4];
  uint8_t ack_num[4];
  uint8_t data_res_ns;
  uint8_t flags;
  #define FIN  0x01
  #define SYN  0x02
  #define RST  0x04
  #define PUSH 0x08
  #define ACK  0x10   
  #define URG  0x20
  #define ECE  0x40
  #define CWR  0x80
  uint8_t window[2];
  uint8_t checksum[2];
  uint8_t urgent_p[2];
  uint8_t options_and_data[0];
}tcp_hdr_t;

// UDP header's structure
typedef struct {
  uint8_t  src_port[2];
  uint8_t dst_port[2];
  uint8_t length[2];
  uint8_t checksum[2];
  uint8_t data[0];
}udp_hdr_t;
/*
 * Hash Table definitions
 */

typedef struct
{
  int proto;
  int state;
  #define OPEN -6
  #define HALFOPEN -7
  #define CONNECTED -8
  #define CLOSING -9
  #define CLOSED -10
  int direction;
}Value;

typedef struct 
{
  uint32_t key;
  uint32_t src_ip;
  uint32_t dst_ip;
  uint16_t src_port;
  uint16_t dst_port;
  int direction;
  int proto;
}Key;

typedef struct Node
{
  Key* key;
  Value* value;
  struct Node* next;
}table_Node;

typedef struct HashTable
{
  int size;
  int number_of_pairs;
  table_Node ** table;
}HashTable;

HashTable* create(int size);
void free_table(HashTable* hashtable);
int size(HashTable* hashtable);
int isEmpty(HashTable* hashtable); //if empty 0, not empty 1
int contains(Key* key, HashTable* hashtable);
Value* get(Key* key,HashTable* hashtable);
int compare_keys(Key* this, Key* other);
uint32_t compute_hash_value(Key *key, HashTable* hashtable);
int put(Key* key, Value* value,HashTable* hashtable);
void delete(Key* key, HashTable* hashtable);