#include "hashtable.h"
//hello world
HashTable* create(int size)
{
	HashTable* the_table =malloc(sizeof(HashTable));
	the_table->table = (Node **)calloc(size,sizeof(Node*));
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
int contains(uint32_t key);
Value* get(uint32_t key,HashTable* hashtable)
{
	if(hashtable == NULL) return NULL;
	unsigned int hash_v = key%hashtable->size;
	Node* node = hashtable->table[hash_v];
	while(node!=NULL)
	{
		if(node->key == key)
			return node->value;
		node = node->next;
	}
	return NULL;
}
int put(uint32_t key, Value* value,HashTable* hashtable)
{
	unsigned int hash_v;
	if(hashtable==NULL) return -1;
	hashtable->number_of_pairs++;
	hash_v = key%hashtable->size;
	Node* new_node = (Node*)calloc(1,sizeof(Node));
	Node* temp = hashtable->table[hash_v];
	new_node->value = value;
	new_node->next = temp;
	new_node->key = key;
	hashtable->table[hash_v] = new_node;
	return 0;
}
void delete(uint32_t key, HashTable* hashtable)
{
	if(hashtable == NULL) return;
	unsigned int hash_v = key%hashtable->size;
	Node* node = hashtable->table[hash_v];
	if(node!=NULL && node->key==key)
	{
		Node* temp = node->next;
		free(node->value);
		free(node);
		hashtable->table[hash_v] = temp;
		hashtable->number_of_pairs--;
		return;
	}
	Node* prev = node;
	Node* cur = prev->next;
	while(cur!=NULL)
	{
		if(cur->key == key)
		{
			prev->next = cur->next;
			free(cur->value);
			free(cur);
			hashtable->number_of_pairs--;
			return;
		}
		prev = cur;
		cur = cur->next;
	}
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
			free(temp->value);
			free(temp);
		}
	}	
	free(hashtable->table);;
	free(hashtable);
}

int main(int argc, char** argv){
	HashTable* new_table = create(1);
	int i=0;
	for(;i<10;i++)
	{
		Value* v = (Value*)calloc(1,sizeof(Value*));
		v->value = i*10;
		put(i,v,new_table);
	}
	for(i=20;i>=0;i--)
	{
		delete(i,new_table);
		Value* v_get = get(i,new_table);
		if(v_get!=NULL)
			printf("%d\n",v_get->value );
	}
	Value* v = (Value*)calloc(1,sizeof(Value*));
	v->value = i*10;
		put(i,v,new_table);
	Value* v_get = get(i,new_table);
		if(v_get!=NULL)
			printf("%d\n",v_get->value );
	free_table(new_table);
	return 0;
}
