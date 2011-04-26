#ifndef _HEAPSORT_H_
#define _HEAPSORT_H_

typedef struct _Callout * heap_nodep;
void make_heap(heap_nodep * head, heap_nodep * tail);
void push_heap(heap_nodep * head, heap_nodep * tail, heap_nodep node);
void shot_heap(heap_nodep * head, heap_nodep * tail, heap_nodep node);
void pop_heap(heap_nodep * head, heap_nodep * tail, heap_nodep * node);
#endif
