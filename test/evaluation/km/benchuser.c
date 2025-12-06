#include <stdio.h>
#include <stdlib.h>
#include <time.h>

#define NUM_ELEMENTS 1024

typedef struct Node {
    int value;
    struct Node *next;
} Node;

Node* create_list(int n) {
    Node *head = NULL;
    Node *current = NULL;
    for (int i = 0; i < n; i++) {
        Node *node = malloc(sizeof(Node));
        node->value = i;
        node->next = NULL;
        if (!head) {
            head = node;
            current = node;
        } else {
            current->next = node;
            current = node;
        }
    }
    return head;
}

Node* find(Node *head, int target) {
    Node *current = head;
    while (current) {
        if (current->value == target)
            return current;
        current = current->next;
    }
    return NULL;
}

int main() {
    Node *head = create_list(NUM_ELEMENTS);

    int target = 512123;

    struct timespec start, end;
    clock_gettime(CLOCK_MONOTONIC, &start);
    Node *found = find(head, target);
    clock_gettime(CLOCK_MONOTONIC, &end);

    long long elapsed_ns = (end.tv_sec - start.tv_sec) * 1000000000LL + (end.tv_nsec - start.tv_nsec);

    if (found) {
        printf("Found value %d\n", found->value);
    } else {
        printf("Value not found\n");
    }
    printf("Search time: %lld ns\n", elapsed_ns);

    Node *current = head;
    while (current) {
        Node *tmp = current;
        current = current->next;
        free(tmp);
    }

    return 0;
}
