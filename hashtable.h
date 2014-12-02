#include <stdint.h>
#include <stdlib.h>
#include <stdio.h>
/*hashtable*/
const int PRIMES[29] = {
   7, 13, 31, 61, 127, 251, 509, 1021, 2039, 4093, 8191, 16381,
   32749, 65521, 131071, 262139, 524287, 1048573, 2097143, 4194301,
   8388593, 16777213, 33554393, 67108859, 134217689, 268435399,
   536870909, 1073741789, 2147483647
};

typedef struct Value
{
	int value;
}Value;

typedef struct Node
{
	uint32_t key;
	Value* value;
	struct Node* next;
}Node;
typedef struct HashTable
{
	int size;
	int number_of_pairs;
	Node ** table;
	
}HashTable;

HashTable* create(int size);
void free_table(HashTable* hashtable);
int size(HashTable* hashtable);
int isEmpty(HashTable* hashtable); //if empty 0, not empty 1
int contains(uint32_t key);
Value* get(uint32_t key,HashTable* hashtable);
int put(uint32_t key, Value* value,HashTable* hashtable);
void delete(uint32_t key, HashTable* hashtable);

