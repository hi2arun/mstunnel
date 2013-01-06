#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <assert.h>
#include "mstrb.h"

#define NODES       1000
//#define PERF_LOOPS  100000
#define PERF_LOOPS  10
#define CHECK_LOOPS 100

typedef unsigned u32;
static int max = 0;

#define WARN_ON_ONCE(condition) assert(!(condition))

struct test_node {
	struct rb_node rb;
	u32 key;

	/* following fields used for testing augmented rbtree functionality */
	u32 val;
	u32 augmented;
};

static struct rb_root root = RB_ROOT;
static struct test_node nodes[NODES];

static void insert(struct test_node *node, struct rb_root *root)
{
	struct rb_node **new = &root->rb_node, *parent = NULL;
	u32 key = node->key;

	while (*new) {
		parent = *new;
		if (key < rb_entry(parent, struct test_node, rb)->key)
			new = &parent->rb_left;
		else
			new = &parent->rb_right;
	}

	rb_link_node(&node->rb, parent, new);
	rb_insert_color(&node->rb, root);
}

static inline void print(struct rb_root *root)
{
    int index = 0;
    struct test_node *tn = NULL;
    struct rb_node *rb_node;

    rb_node = rb_first(root);

    if (rb_node) {
        while(rb_node) {
            tn = rb_entry(rb_node, struct test_node, rb);;
            if (tn) {
                fprintf(stderr, "[%d] [%p] Key [%d] val [%d]\n", index, (void *)tn, tn->key, tn->val);
            }
            index++;
            rb_node = rb_next(rb_node);
        }
    }
    else {
        fprintf(stderr, "Tree is empty\n");
    }

    return;
}

static inline struct test_node *search(u32 key, struct rb_root *root)
{
    int index = 0;
    struct test_node *tn = NULL;
    struct rb_node *rb_node;
    
    rb_node = rb_first(root);
    if (rb_node) {
        while(rb_node) {
            tn = rb_entry(rb_node, struct test_node, rb);;
            if (tn && (key == tn->key)) {
                if (index > max) {
                    max = index;
                }
                //fprintf(stderr, "[%d] [%p] Key [%d] val [%d]\n", index, (void *)tn, tn->key, tn->val);
                return tn;
            }
            index++;
            rb_node = rb_next(rb_node);
        }
    }
    fprintf(stderr, "Tree is empty\n");

    return NULL;
}


static inline void erase(struct test_node *node, struct rb_root *root)
{
	rb_erase(&node->rb, root);
}

static void init(void)
{
	int i;
    //int key = 0;
	for (i = 0; i < NODES; i++) {
		nodes[i].key = rand();
		nodes[i].val = rand();
	}
}

static int is_red(struct rb_node *rb)
{
	return !(rb->rb_parent_color & 1);
}

static int black_path_count(struct rb_node *rb)
{
	int count;
	for (count = 0; rb; rb = rb_parent(rb))
		count += !is_red(rb);
	return count;
}

static void check(int nr_nodes)
{
	struct rb_node *rb;
	int count = 0;
	int blacks;
	u32 prev_key = 0;

	for (rb = rb_first(&root); rb; rb = rb_next(rb)) {
		struct test_node *node = rb_entry(rb, struct test_node, rb);
		WARN_ON_ONCE(node->key < prev_key);
		WARN_ON_ONCE(is_red(rb) &&
			     (!rb_parent(rb) || is_red(rb_parent(rb))));
		if (!count)
			blacks = black_path_count(rb);
		else
			WARN_ON_ONCE((!rb->rb_left || !rb->rb_right) &&
				     blacks != black_path_count(rb));
		prev_key = node->key;
		count++;
	}
	WARN_ON_ONCE(count != nr_nodes);
}

static int rbtree_test_init(void)
{
	int i, j;
	printf("rbtree testing\n");

	init();

	for (i = 0; i < PERF_LOOPS; i++) {
        for (j = 0; j < NODES; j++)
            insert(nodes + j, &root);
        //print(&root);
		for (j = 0; j < NODES; j++) {
            search(nodes[j].key, &root);
			erase(nodes + j, &root);
        }
        fprintf(stderr, "After erase: %d\n", max);
        print(&root);
	}

	for (i = 0; i < CHECK_LOOPS; i++) {
		init();
		for (j = 0; j < NODES; j++) {
			check(j);
			insert(nodes + j, &root);
		}
		for (j = 0; j < NODES; j++) {
			check(NODES - j);
			erase(nodes + j, &root);
		}
		check(0);
	}

	return 0;
}

int main(void) 
{
    return rbtree_test_init();
}

