#include <assert.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <limits.h>

#define SIZE_ARRAY 16
#define SIZE_LINE 4
#define GOAL 0xfedcba9876543210LL
#define MAX_STATES 300000000

// Structure pour un nœud dans A*
typedef struct Node {
    long long state;
    int g_cost;  // coût depuis le départ
    int f_cost;  // g_cost + heuristique
    int parent_idx;
    char move;   // 'U', 'D', 'L', 'R'
} Node;

// Priority queue simple (min-heap)
typedef struct {
    int *indices;
    int size;
    int capacity;
} PriorityQueue;

// Hash table pour les états visités
typedef struct {
    long long *states;
    int *indices;
    int size;
    int capacity;
} HashTable;

void shuffle_array(int *array) {
    int i;
    for (i = 0; i < SIZE_ARRAY - 1; i++) {
        int j = i + rand() / (RAND_MAX / (SIZE_ARRAY - i) + 1);
        int t = array[j];
        array[j] = array[i];
        array[i] = t;
    }
}

void print_array(int* array) {
    for (int i = 0; i < SIZE_LINE; i++) {
        for (int j = 0; j < SIZE_LINE; j++)
            printf("%2d ", array[i * 4 + j]);
        printf("\n");
    }
}

int get_possible_move(int* array) {
    int pos_0 = -1;
    for (int i = 0; i < SIZE_ARRAY; i++) {
        if (array[i] == 0) {
            pos_0 = i;
            break;
        }
    }
    int possibilities = 0;
    if (pos_0 >= SIZE_LINE) {
        possibilities |= (1 << 3);  // U
    }
    if (pos_0 % SIZE_LINE != 0) {
        possibilities |= (1 << 2);  // L
    }
    if (pos_0 % SIZE_LINE != 3) {
        possibilities |= (1 << 1);  // R
    }
    if (pos_0 < SIZE_ARRAY - SIZE_LINE) {
        possibilities |= (1 << 0);  // D
    }
    return possibilities;
}

int count_set_bits(unsigned int num) {
    int count = 0;
    while (num) {
        count += num & 1;
        num >>= 1;
    }
    return count;
}

long long pack_nibbles(int* array) {
    long long qword = 0;
    for (int i = 0; i < SIZE_ARRAY; i++) {
        qword |= ((long long)(array[i] & 0xF)) << (i * 4);
    }
    return qword;
}

void unpack_nibbles(long long value, int* array) {
    for (int i = 0; i < SIZE_ARRAY; i++) {
        array[i] = (value >> (i * 4)) & 0xF;
    }
}

// Trouver la position de 0 dans l'état packÉ
int find_zero_pos(long long state) {
    for (int i = 0; i < SIZE_ARRAY; i++) {
        if (((state >> (i * 4)) & 0xF) == 0) {
            return i;
        }
    }
    return -1;
}

// Appliquer un mouvement (U=0, L=1, R=2, D=3)
long long apply_move(long long state, int move) {
    int array[SIZE_ARRAY];
    unpack_nibbles(state, array);
    
    int pos_0 = find_zero_pos(state);
    int swap_pos = -1;
    
    if (move == 3 && pos_0 >= SIZE_LINE) {  // Up
        swap_pos = pos_0 - SIZE_LINE;
    } else if (move == 2 && pos_0 % SIZE_LINE != 0) {  // Left
        swap_pos = pos_0 - 1;
    } else if (move == 1 && pos_0 % SIZE_LINE != 3) {  // Right
        swap_pos = pos_0 + 1;
    } else if (move == 0 && pos_0 < SIZE_ARRAY - SIZE_LINE) {  // Down
        swap_pos = pos_0 + SIZE_LINE;
    }
    
    if (swap_pos != -1) {
        int temp = array[pos_0];
        array[pos_0] = array[swap_pos];
        array[swap_pos] = temp;
        return pack_nibbles(array);
    }
    
    return state;
}

// Distance de Manhattan pour l'heuristique
int manhattan_distance(long long state) {
    int distance = 0;
    int array[SIZE_ARRAY];
    unpack_nibbles(state, array);
    
    for (int i = 0; i < SIZE_ARRAY; i++) {
        int value = array[i];
        if (value == 0) continue;
        
        int goal_pos = value;
        int current_row = i / SIZE_LINE;
        int current_col = i % SIZE_LINE;
        int goal_row = goal_pos / SIZE_LINE;
        int goal_col = goal_pos % SIZE_LINE;
        
        distance += abs(current_row - goal_row) + abs(current_col - goal_col);
    }
    
    return distance;
}

// Hash table functions
HashTable* create_hash_table(int capacity) {
    HashTable *ht = malloc(sizeof(HashTable));
    ht->capacity = capacity;
    ht->size = 0;
    ht->states = calloc(capacity, sizeof(long long));
    ht->indices = malloc(capacity * sizeof(int));
    for (int i = 0; i < capacity; i++) {
        ht->indices[i] = -1;
    }
    return ht;
}

int hash_function(long long state, int capacity) {
    return (int)((state ^ (state >> 32)) % capacity);
}

int hash_table_find(HashTable *ht, long long state) {
    int hash = hash_function(state, ht->capacity);
    int start = hash;
    
    while (ht->indices[hash] != -1) {
        if (ht->states[hash] == state) {
            return ht->indices[hash];
        }
        hash = (hash + 1) % ht->capacity;
        if (hash == start) break;
    }
    return -1;
}

void hash_table_insert(HashTable *ht, long long state, int index) {
    int hash = hash_function(state, ht->capacity);
    
    while (ht->indices[hash] != -1) {
        if (ht->states[hash] == state) {
            return;
        }
        hash = (hash + 1) % ht->capacity;
    }
    
    ht->states[hash] = state;
    ht->indices[hash] = index;
    ht->size++;
}

// Priority Queue functions
PriorityQueue* create_pq(int capacity) {
    PriorityQueue *pq = malloc(sizeof(PriorityQueue));
    pq->indices = malloc(capacity * sizeof(int));
    pq->size = 0;
    pq->capacity = capacity;
    return pq;
}

void pq_swap(PriorityQueue *pq, int i, int j) {
    int temp = pq->indices[i];
    pq->indices[i] = pq->indices[j];
    pq->indices[j] = temp;
}

void pq_heapify_up(PriorityQueue *pq, Node *nodes, int idx) {
    while (idx > 0) {
        int parent = (idx - 1) / 2;
        if (nodes[pq->indices[idx]].f_cost < nodes[pq->indices[parent]].f_cost) {
            pq_swap(pq, idx, parent);
            idx = parent;
        } else {
            break;
        }
    }
}

void pq_heapify_down(PriorityQueue *pq, Node *nodes, int idx) {
    while (1) {
        int smallest = idx;
        int left = 2 * idx + 1;
        int right = 2 * idx + 2;
        
        if (left < pq->size && nodes[pq->indices[left]].f_cost < nodes[pq->indices[smallest]].f_cost) {
            smallest = left;
        }
        if (right < pq->size && nodes[pq->indices[right]].f_cost < nodes[pq->indices[smallest]].f_cost) {
            smallest = right;
        }
        
        if (smallest != idx) {
            pq_swap(pq, idx, smallest);
            idx = smallest;
        } else {
            break;
        }
    }
}

void pq_push(PriorityQueue *pq, Node *nodes, int node_idx) {
    pq->indices[pq->size] = node_idx;
    pq_heapify_up(pq, nodes, pq->size);
    pq->size++;
}

int pq_pop(PriorityQueue *pq, Node *nodes) {
    int result = pq->indices[0];
    pq->size--;
    if (pq->size > 0) {
        pq->indices[0] = pq->indices[pq->size];
        pq_heapify_down(pq, nodes, 0);
    }
    return result;
}

// A* algorithm
char* find_solution(long long start) {
    if (start == GOAL) {
        char *result = malloc(2);
        result[0] = '\0';
        return result;
    }
    
    Node *nodes = malloc(MAX_STATES * sizeof(Node));
    HashTable *visited = create_hash_table(MAX_STATES * 2);
    PriorityQueue *open_set = create_pq(MAX_STATES);
    
    int node_count = 0;
    nodes[node_count].state = start;
    nodes[node_count].g_cost = 0;
    nodes[node_count].f_cost = manhattan_distance(start);
    nodes[node_count].parent_idx = -1;
    nodes[node_count].move = ' ';
    
    hash_table_insert(visited, start, node_count);
    pq_push(open_set, nodes, node_count);
    node_count++;
    
    char move_chars[] = {'2', '3', '1', '0'};

    while (open_set->size > 0) {
        int current_idx = pq_pop(open_set, nodes);
        Node current = nodes[current_idx];
        
        if (current.state == GOAL) {
            // Reconstruire le chemin
            int path_length = current.g_cost;
            char *path = malloc(path_length + 1);
            path[path_length] = '\0';
            
            int idx = current_idx;
            for (int i = path_length - 1; i >= 0; i--) {
                path[i] = nodes[idx].move;
                idx = nodes[idx].parent_idx;
            }
            
            free(nodes);
            free(visited->states);
            free(visited->indices);
            free(visited);
            free(open_set->indices);
            free(open_set);
            
            return path;
        }

        int array[SIZE_ARRAY];
        unpack_nibbles(current.state, array);
        int possibilities = get_possible_move(array);
        
        for (int move = 0; move < 4; move++) {
            if (!(possibilities & (1 << move))) continue;
            
            long long new_state = apply_move(current.state, move);
            int existing_idx = hash_table_find(visited, new_state);
            int new_g = current.g_cost + 1;
            
            if (existing_idx == -1) {
                if (node_count >= MAX_STATES) {
                    printf("Trop d'états explorés!\n");
                    free(nodes);
                    free(visited->states);
                    free(visited->indices);
                    free(visited);
                    free(open_set->indices);
                    free(open_set);
                    return NULL;
                }
                
                nodes[node_count].state = new_state;
                nodes[node_count].g_cost = new_g;
                nodes[node_count].f_cost = new_g + manhattan_distance(new_state);
                nodes[node_count].parent_idx = current_idx;
                nodes[node_count].move = move_chars[move];
                
                hash_table_insert(visited, new_state, node_count);
                pq_push(open_set, nodes, node_count);
                node_count++;
            }
        }
    }
    
    free(nodes);
    free(visited->states);
    free(visited->indices);
    free(visited);
    free(open_set->indices);
    free(open_set);
    
    return NULL;
}

int main() {
    srand(time(NULL));
    int start[SIZE_ARRAY] = {5, 2, 4, 3, 10, 8, 12, 9, 14, 1, 7, 0, 13, 15, 6, 11};
    //shuffle_array(start);
    
    printf("État initial:\n");
    print_array(start);
    printf("\n");
    
    long long packed = pack_nibbles(start);
    printf("Packed: %llx\n", packed);
    printf("Goal:   %llx\n\n", GOAL);
    
    printf("Recherche de la solution...\n");
    char *solution = find_solution(packed);
    
    if (solution) {
        printf("Solution trouvée! (%d mouvements)\n", (int)strlen(solution));
        printf("Mouvements: %s\n", solution);
        free(solution);
    } else {
        printf("Pas de solution trouvée!\n");
    }
    
    return 0;
}
