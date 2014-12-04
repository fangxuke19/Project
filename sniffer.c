/*
 * sniffer skeleton (Linux kernel module)
 *
 * Copyright (C) 2014 Ki Suh Lee <kslee@cs.cornell.edu>
 * based on netslice implementation of Tudor Marian <tudorm@cs.cornell.edu>
 */

#include <linux/module.h>
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
#include <net/ip.h>
#include <net/tcp.h>
#include <linux/sched.h>
#include <linux/wait.h>
#include <linux/proc_fs.h>
#include <linux/string.h>
#include <linux/seq_file.h>
#include "sniffer_ioctl.h"

MODULE_AUTHOR("XUKE FANG");
MODULE_DESCRIPTION("CS5413 Packet Filter / Sniffer Framework");
MODULE_LICENSE("Dual BSD/GPL");

static dev_t sniffer_dev;
static struct cdev sniffer_cdev;
static int sniffer_minor = 1;
atomic_t refcnt;

static int hook_chain_in = NF_INET_PRE_ROUTING;// | NF_INET_POST_ROUTING;
static int hook_prio_in = NF_IP_PRI_FIRST;
struct nf_hook_ops nf_hook_ops_in;

static int hook_chain_out = NF_INET_POST_ROUTING;
static int hook_prio_out = NF_IP_PRI_FIRST;
struct nf_hook_ops nf_hook_ops_out;
//the hashtable
HashTable* the_table;
//semaphores
struct semaphore dev_sem;
struct semaphore hash_sem;
wait_queue_head_t readqueue;

// skb buffer between kernel and user space
struct list_head skbs;
struct list_head rule_head; 
// skb wrapper for buffering
struct skb_list 
{
    struct list_head list;
    struct sk_buff *skb;
};
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
    HashTable* the_table =vmalloc(sizeof(HashTable));
    the_table->table = (Node **)vmalloc(size*sizeof(Node*));
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
   //  printk(KERN_DEBUG "88888888888888!!!!!!!!!! \n");
    if(hashtable == NULL) return NULL;
     //printk(KERN_DEBUG "999999999999!!!!!!!!!! \n");
    uint32_t hash_v =compute_hash_value(key,hashtable);
     //printk(KERN_DEBUG "101010101010101!!!!!!!!!! \n");
    Node* node = hashtable->table[hash_v];
    //printk(KERN_DEBUG "AAAAAAAAAAAAAAAAA!!!!!!!!!! \n");
    //if(node==NULL)
    //printk(KERN_DEBUG "NODE IS WRONG!!!!!!!!!!!! \n");   
    while(node!=NULL)
    {
      //  printk(KERN_DEBUG "IN WHILE !!!!!!!!!!!!!!!! \n");   
        //  if(!node->key)
    //printk(KERN_DEBUG "NODE KEY IS WRONG!!!!!!!!!!!! \n");   
        if(compare_keys(node->key,key))
            return node->value;
        node = node->next;
    }
     //printk(KERN_DEBUG "OUT WHILE !!!!!!!!!!!!!!!! \n");   
    return NULL;
}
int put(Key* key, Value* value,HashTable* hashtable)
{
    uint32_t hash_v;
    if(hashtable==NULL) return -1;
    hashtable->number_of_pairs++;
    hash_v =compute_hash_value(key,hashtable);
    Node* new_node = (Node*)kmalloc(sizeof(Node),GFP_ATOMIC);
    Node* temp = hashtable->table[hash_v];
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
    Node* node = hashtable->table[hash_v];
        
    if(node!=NULL && compare_keys(key,node->key)==1)
    {
        //printk(KERN_DEBUG "DELETING HEAD !!!!!!!!!!!!!!!! \n");   
        Node* temp = node->next;
        //printk(KERN_DEBUG "FFFFFFFFFFFFFF !!!!!!!!!!!!!!!! \n");   
        kfree(node->value);
        //printk(KERN_DEBUG "GGGGGGGGGGG !!!!!!!!!!!!!!!! \n");   
        kfree(node->key);
        //printk(KERN_DEBUG "HHHHHHHHHHHH !!!!!!!!!!!!!!!! \n");   
        kfree(node);
        //printk(KERN_DEBUG "IIIIIIIIIIIIIIIIII !!!!!!!!!!!!!!!! \n");   
        hashtable->table[hash_v] = temp;
        hashtable->number_of_pairs--;
        return;
    }
    Node* prev = node;
    Node* cur = prev->next;
    while(cur!=NULL)
    {
        if(compare_keys(cur->key, key))
        {
          //  printk(KERN_DEBUG "DELETING !!!!!!!!!!!!!!!! \n");   
            prev->next = cur->next;
            //printk(KERN_DEBUG "QQQQQQQQQQQQQQQ!!!!!!!!!!!!!!!! \n");   
            kfree(cur->value);
            //printk(KERN_DEBUG "WWWWWWWWWWWWWWWW !!!!!!!!!!!!!!!! \n");   
            kfree(cur->key);
            //printk(KERN_DEBUG "EEEEEEEEEEEEEEEEEEE !!!!!!!!!!!!!!!! \n");   
            kfree(cur);
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
     printk(KERN_DEBUG "IN THE COMPARE !!!!!!!!!!!!!!!! \n");   
    if( this->proto == other->proto &&this->src_port == other->src_port && this->dst_port == other->dst_port && this->dst_ip == other->dst_ip && this->src_ip == other->src_ip)
      {
         printk(KERN_DEBUG " COMPARing !!!!!!!!!!!!!!!! \n");   
        return 1;   
      }  
           printk(KERN_DEBUG " COMPARing +++!!!!!!!!!!!!!!!! \n");     
    return 0;
    
}
void free_table(HashTable* hashtable)
{
    if(hashtable==NULL) return;
    int i=0;
    for(;i<hashtable->size;i++)
    {
        Node* node = hashtable->table[i];
        Node* temp;
        while(node!=NULL)
        {
            temp = node;
            node = node->next;
            kfree(temp->value);
            kfree(temp->key);
            kfree(temp);
        }
    }   
    vfree(hashtable->table);;
    vfree(hashtable);
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
/* From kernel to userspace */
static ssize_t 
sniffer_fs_read(struct file *file, char __user *buf, size_t count, loff_t *pos)
{
    struct skb_list* pos_node;
    struct skb_list* n;
   // if (down_interruptible(&dev_sem))
   //      return -ERESTARTSYS;
   //  printk(KERN_DEBUG "where are here");
   //  while(list_empty(&skbs))
   //  {
   //      up(&dev_sem);
   //     if (file->f_flags & O_NONBLOCK)
     //       return -EAGAIN;
      //  printk(KERN_DEBUG "going to sleep");
        if(atomic_read(&refcnt)>0)
            return -EBUSY;
         printk(KERN_DEBUG "refcnt%d",atomic_read(&refcnt));
         atomic_set(&refcnt,1);
        if (wait_event_interruptible(readqueue, (!list_empty(&skbs))))
        {
             atomic_set(&refcnt,0);
              return -ERESTARTSYS; 
        }
           
        if(list_empty(&skbs))           
            return -1;
      //  if (down_interruptible(&dev_sem))
        //    return -ERESTARTSYS;
    //}
   
    list_for_each_entry_safe(pos_node,n,&skbs,list)
    {
       
        copy_to_user(buf,pos_node->skb->data,pos_node->skb->len);
         down_interruptible(&dev_sem);
        list_del(&pos_node->list);
          up (&dev_sem);
          atomic_set(&refcnt,0);
        break;
    }
    // up (&dev_sem);
    return pos_node->skb->len;
}

static int sniffer_fs_open(struct inode *inode, struct file *file)
{
    struct cdev *cdev = inode->i_cdev;
    int cindex = iminor(inode);

    if (!cdev) {
        printk(KERN_ERR "cdev error\n");
        return -ENODEV;
    }

    if (cindex != 0) {
        printk(KERN_ERR "Invalid cindex number %d\n", cindex);
        return -ENODEV;
    }

    return 0;
}

static int sniffer_fs_release(struct inode *inode, struct file *file)
{
    return 0;
}

static long sniffer_fs_ioctl(struct file *file, unsigned int cmd, unsigned long arg)
{
    long err =0 ;
    node* new_node = vmalloc(sizeof(node));
    struct sniffer_flow_entry * converted_arg;

    if (_IOC_TYPE(cmd) != SNIFFER_IOC_MAGIC)
        return -ENOTTY; 
    if (_IOC_NR(cmd) > SNIFFER_IOC_MAXNR)
        return -ENOTTY;
    if (_IOC_DIR(cmd) & _IOC_READ)
        err = !access_ok(VERIFY_WRITE, (void __user *)arg, _IOC_SIZE(cmd));
    if (_IOC_DIR(cmd) & _IOC_WRITE)
        err = !access_ok(VERIFY_READ, (void __user *)arg, _IOC_SIZE(cmd));
    if (err)
        return -EFAULT;

    converted_arg = (struct sniffer_flow_entry *)arg;
    
        //INIT_LIST_HEAD(&(new_node->list));
        new_node->src_ip = converted_arg->src_ip;
       //  printk(KERN_DEBUG "++++++++src_ip:%x\n",converted_arg->src_ip);
        new_node->dst_ip = converted_arg->dst_ip;
        new_node->src_port = converted_arg->src_port;
       // printk(KERN_DEBUG "++++++++src_port:%x\n",converted_arg->src_port);
        new_node->dst_port = converted_arg->dst_port;
        new_node->action = converted_arg->action;
        new_node->direction = converted_arg->direction;
        new_node->interface = vmalloc(10*sizeof(char));
        strcpy(new_node->interface,converted_arg->interface);
        if(new_node->interface)
            printk(KERN_DEBUG "INTERFACE:%s", new_node->interface);
        new_node->proto = converted_arg->proto;
    switch(cmd) {
    case SNIFFER_FLOW_ENABLE:
        new_node->mode =1;
        if (down_interruptible(&dev_sem))
            return -ERESTARTSYS;
        list_add(&new_node->list,&rule_head);
        up(&dev_sem);

        break;

    case SNIFFER_FLOW_DISABLE:
        new_node->mode =0;
        if (down_interruptible(&dev_sem))
            return -ERESTARTSYS;
        list_add(&new_node->list,&rule_head);
        up(&dev_sem);
        break;
    default:
        vfree(new_node);
        printk(KERN_DEBUG "Unknown command\n");
        err = -EINVAL;
    }

    return err;
}
void print_ip(unsigned char* bytes,uint32_t ip)
{
    //unsigned char bytes[4];
    bytes[0] = ip & 0xFF;
    bytes[1] = (ip >> 8) & 0xFF;
    bytes[2] = (ip >> 16) & 0xFF;
    bytes[3] = (ip >> 24) & 0xFF; 
}
static int sniffer_proc_show(struct seq_file *m, void *v) {
    struct node* pos;
    int count =1;
    unsigned char ip[4];
    seq_printf(m, "      [command] [proto]  [interface] [src_ip]       [src_port]  [dst_ip]       [dst_port] [action]\n");
    list_for_each_entry(pos,&rule_head,list)
    {
        int max_width = 20;
        char* any = "any";
        if(pos->mode == 1)
            seq_printf(m,"%d      enable",count);
        else 
            seq_printf(m,"%d      disable",count);
        if(pos->proto == TCP)
             seq_printf(m,"   TCP");
        else if(pos->proto == UDP){
            seq_printf(m,"   UDP");
        }
        else
        {
             seq_printf(m,"   ICMP");
        }
        seq_printf(m,"   %s",pos->interface);
        
        if(pos->src_ip == 0)
            seq_printf(m,"   any");
        else
        {
            print_ip(ip,pos->src_ip);
            seq_printf(m,"   %d.%d.%d.%d",ip[3],ip[2],ip[1],ip[0]);
        }
          
         if(pos->src_port == 0)
            seq_printf(m,"%*s",max_width,any);
        else
            seq_printf(m,"%8d   ",ntohs(pos->src_port));
         if(pos->dst_ip == 0)
            seq_printf(m,"       any");
        else
        {
            print_ip(ip,pos->dst_ip);
            seq_printf(m,"   %d.%d.%d.%d",ip[3],ip[2],ip[1],ip[0]);
        }
         if(pos->dst_port == 0)
            seq_printf(m,"            any");
        else
            seq_printf(m,"          %d   ",ntohs(pos->dst_port));
         if(pos->action == 0)
            seq_printf(m,"       None");
        else if(pos->action == CAPTURING)
            seq_printf(m,"       Capture");
        else 
             seq_printf(m,"       DPI");
       
        seq_printf(m,"\n");
        count++;
    }
  
  return 0;
}

static int sniffer_proc_open(struct inode *inode, struct  file *file) {
  return single_open(file, sniffer_proc_show, NULL);
}
static struct file_operations sniffer_fops = {
    .open = sniffer_fs_open,
    .release = sniffer_fs_release,
    .read = sniffer_fs_read,
    .unlocked_ioctl = sniffer_fs_ioctl,
    .owner = THIS_MODULE,
};
static const struct file_operations  proc_fops = {
     .owner = THIS_MODULE,
     .open  = sniffer_proc_open,
     .read  = seq_read,
     .llseek = seq_lseek,
     .release = single_release,
 };

static unsigned int sniffer_nf_hook(unsigned int hook, struct sk_buff* skb,
        const struct net_device *indev, const struct net_device *outdev,
        int (*okfn) (struct sk_buff*))
{
    printk(KERN_DEBUG "HOOK!!! \n");
    struct iphdr *iph = ip_hdr(skb);
    node* pos;
    int direction=OUT;

    Key* key = kmalloc(sizeof(Key),GFP_ATOMIC);
    struct net_device *dev= outdev;
     if(indev!= NULL){
        direction = IN;
        dev = indev;
        //printk(KERN_DEBUG "In device :%s\n", dev->name);
     }
     // if(outdev!=NULL){
     //    // printk(KERN_DEBUG "Out device: %s\n",dev->name);
     // }
    if (iph->protocol == IPPROTO_TCP) {
        struct tcphdr *tcph = ip_tcp_hdr(iph);
        key->src_ip = ntohl(iph->saddr);
        key->dst_ip = ntohl(iph->daddr);
        key->src_port = tcph->source;
        key->dst_port = tcph->dest;
        key->proto = TCP;
        uint8_t flag = *((uint8_t*)tcph+13);
        printk(KERN_DEBUG "TCP from :%pI4: to :%pI4 src_port:%d dst_port:%d flag:%d \n",&iph->saddr,&iph->daddr,tcph->source,tcph->dest,flag);
        if(key==NULL)
            printk(KERN_DEBUG "key is NULL!!!!!!!!!! \n");
        if(the_table == NULL)
            printk(KERN_DEBUG "table is NULL!!!!!!!!!! \n");
        if(contains(key,the_table)==1)
        {
            printk(KERN_DEBUG "HASH TABLE CONTAINS \n ");
            //return NF_ACCEPT;
            Value* value = get(key,the_table);
            Key* key_ = kmalloc(sizeof(struct skb_list),GFP_ATOMIC);
            key_->src_ip = ntohl(iph->daddr);
            key_->dst_ip = ntohl(iph->saddr);
            key_->src_port = tcph->dest;
            key_->dst_port = tcph->source;
            key_->proto = TCP;
            if( (tcph->fin | tcph->rst))
            {
                if (down_interruptible(&hash_sem))
                    return -ERESTARTSYS;
                delete(key,the_table);
                if(contains(key_,the_table)==1)
                    delete(key_,the_table);
                up(&hash_sem);
                printk(KERN_DEBUG "ACCEPT and recieved FIN --from Hashtable rst is %d, fin is %d\n ",tcph->rst,tcph->fin);
                return NF_ACCEPT;
            }
            else if(value->state == OPEN && (tcph->ack && !tcph->syn) ) 
            {
                value->state = CONNECTED; //has to be chan<p></p>ge 
                Value* v = kmalloc(sizeof(Value),GFP_ATOMIC);
                v->proto =TCP;
                v->state = CONNECTED; 
                 if (down_interruptible(&hash_sem))
                    return -ERESTARTSYS;
                put(key_,v,the_table);
                up(&hash_sem);
                printk(KERN_DEBUG "ACCEPT --from Hashtable\n ");
                return NF_ACCEPT;
            } 
            else if(value->state == CONNECTED && (tcph->ack && !tcph->syn))
            {
                 printk(KERN_DEBUG "free key_ 1\n ");
                kfree(key_);
                printk(KERN_DEBUG "ACCEPT --from Hashtable\n ");
                return NF_ACCEPT;
            }
            else
            {
                printk(KERN_DEBUG "NF_DROP --from Hashtable\n ");
                printk(KERN_DEBUG "free key_ 2\n ");
                kfree(key_);
                return NF_DROP;
            }
        } 
        printk(KERN_DEBUG "DOES NOT CONTAINS \n");

        list_for_each_entry(pos,&rule_head,list)
        {
            if( (pos->src_ip == ntohl(iph->saddr) || pos->src_ip == 0)\
                && (pos->dst_ip == ntohl(iph->daddr) || pos->dst_ip == 0)\
                && (pos->src_port == tcph->source || pos->src_port == 0)\
                && (pos->dst_port == tcph->dest || pos->dst_port == 0) \
                && (pos->proto == TCP) \
                && (pos->direction == direction || pos->direction == ALL)\
                && ((strncmp(pos->interface,dev->name,IFNAMSIZ)==0) || (strcmp(pos->interface,"ALL")==0)) )
            {
                // if(pos->action == DPI)
                // {
                //     int length = skb->len;
                //     int p_length = strlen(PATTERN);
                //     int match = 0;
                //     ip_hdr_t* ip_h = (ip_hdr_t *) skb->data;
                //     tcp_hdr_t* tcp_h = (tcp_hdr_t *) ip_h->options_and_data;
                //     unsigned char* data = tcp_h->options_and_data;
                //     int i=0;
                //     for(;i<length;i++)
                //     {
                //         int j =0;
                //         match  =1;
                //         for(;j<p_length;j++)
                //         {
                //             if(data[i+j] != PATTERN[j])     
                //             {
                //                 match =0;
                //                 break;
                //             }               
                //         }
                //         if(match)
                //             break;
                //     }
                //     if(match)
                //         pos->mode = 0;
                // }
                // if(pos->action == CAPTURING)
                // {
                //     struct skb_list* node= kmalloc(sizeof(struct skb_list),GFP_ATOMIC);   
                //     node->skb = skb_copy(skb,GFP_ATOMIC);
                //     if (down_interruptible(&dev_sem))
                //         return -ERESTARTSYS;
                //     list_add_tail(&node->list,&skbs);
                //     if(list_is_last(&node->list,&skbs));
                //         wake_up_interruptible(&readqueue);
                //     up(&dev_sem);
                // }
                if(pos->mode == 0)
                {
                    return NF_DROP;
                }
                Value* v = kmalloc(sizeof(Value),GFP_ATOMIC);
                v->proto =TCP;
                v->state = OPEN; 
                if (down_interruptible(&hash_sem))
                    return -ERESTARTSYS;
                put(key,v,the_table);
                up(&hash_sem);
                printk("TCP_ACCEPT -- from list");
                return NF_ACCEPT; 
            }
        }
        return NF_DROP;
    }
     //kfree(key);
    if( iph->protocol == IPPROTO_ICMP)
    {
         list_for_each_entry(pos,&rule_head,list)
        {
            if( (pos->src_ip == ntohl(iph->saddr) || pos->src_ip == 0)\
                && (pos->dst_ip == ntohl(iph->daddr) || pos->dst_ip == 0)\
                && (pos->proto == ICMP)
                && (pos->direction == direction || pos->direction == ALL)\
                && ((strncmp(pos->interface,dev->name,IFNAMSIZ)==0) || (strcmp(pos->interface,"ALL")==0)) )
            {
                if(pos->mode == 0)
                {
                      return NF_DROP;
                }
                    return NF_ACCEPT; 
            }
        }
        return NF_DROP;
    }
    if(iph->protocol == IPPROTO_UDP)
    {
        struct udphdr *udp_h = ip_udp_hdr(iph);
        if(dev == NULL) 
        {
            printk(KERN_DEBUG "bug!!!!\n");
            return NF_DROP;
        }
        list_for_each_entry(pos,&rule_head,list)
        {
            printk  (KERN_DEBUG  "dev->name:%s\n",dev->name);
            if( (pos->src_ip == ntohl(iph->saddr) || pos->src_ip == 0)\
                && (pos->dst_ip == ntohl(iph->daddr) || pos->dst_ip == 0)\
                && (pos->src_port == udp_h->source || pos->src_port == 0)\
                && (pos->dst_port == udp_h->dest || pos->dst_port == 0) \
                && (pos->proto == UDP)
                && (pos->direction == direction || pos->direction == ALL)\
                && ((strncmp(pos->interface,dev->name,IFNAMSIZ)==0) || (strcmp(pos->interface,"ALL")==0)) )
            {
                 if(pos->mode == 0)
                {
                      return NF_DROP;
                }
                    return NF_ACCEPT; 
            }
        }
        return NF_DROP;
    }
    return NF_ACCEPT;
}

static int __init sniffer_init(void)
{
    int status = 0;
    the_table = create(65521);
    printk(KERN_DEBUG "sniffer_init\n"); 
    if(proc_create("sniffer",0,NULL,&proc_fops)<0)
    {
          printk(KERN_ERR "sniffer proc initi failed\n");
          goto out;
    }
    status = alloc_chrdev_region(&sniffer_dev, 0, sniffer_minor, "sniffer");
    if (status <0) {
        printk(KERN_ERR "alloc_chrdev_retion failed %d\n", status);
        goto out;
    }

    cdev_init(&sniffer_cdev, &sniffer_fops);
    status = cdev_add(&sniffer_cdev, sniffer_dev, sniffer_minor);
    if (status < 0) {
        printk(KERN_ERR "cdev_add failed %d\n", status);
        goto out_cdev;
        
    }

    atomic_set(&refcnt, 0);
    INIT_LIST_HEAD(&skbs);
    INIT_LIST_HEAD(&rule_head);
    init_waitqueue_head(&readqueue);
    sema_init(&dev_sem, 1);
    sema_init(&hash_sem, 1);

    /* register netfilter hook */
    memset(&nf_hook_ops_in, 0, sizeof(nf_hook_ops_in));
    nf_hook_ops_in.hook = sniffer_nf_hook;
    nf_hook_ops_in.pf = PF_INET;
    nf_hook_ops_in.hooknum = hook_chain_in;
    nf_hook_ops_in.priority = hook_prio_in;
    status = nf_register_hook(&nf_hook_ops_in);
    if (status < 0) {
        printk(KERN_ERR "nf_register_hook failed\n");
        goto out_add;
    }

    memset(&nf_hook_ops_out, 0, sizeof(nf_hook_ops_out));
    nf_hook_ops_out.hook = sniffer_nf_hook;
    nf_hook_ops_out.pf = PF_INET;
    nf_hook_ops_out.hooknum = hook_chain_out;
    nf_hook_ops_out.priority = hook_prio_out;
    status = nf_register_hook(&nf_hook_ops_out);
    if (status < 0) {
        printk(KERN_ERR "nf_register_hook failed\n");
        goto out_add;
    }
    return 0;

out_add:
    cdev_del(&sniffer_cdev);
out_cdev:
    unregister_chrdev_region(sniffer_dev, sniffer_minor);
out:
    return status;
}

static void __exit sniffer_exit(void)
{
    //free_list();
    if (nf_hook_ops_in.hook) {
        nf_unregister_hook(&nf_hook_ops_in);
        memset(&nf_hook_ops_in, 0, sizeof(nf_hook_ops_in));
    }
    if (nf_hook_ops_out.hook) {
        nf_unregister_hook(&nf_hook_ops_out);
        memset(&nf_hook_ops_out, 0, sizeof(nf_hook_ops_out));
    }
    cdev_del(&sniffer_cdev);
    unregister_chrdev_region(sniffer_dev, sniffer_minor);
    remove_proc_entry("sniffer", NULL);;
}

module_init(sniffer_init);
module_exit(sniffer_exit);
