void test_kernel_api(void) {
    // Initialize head element
    struct list_head list_head;
    INIT_LIST_HEAD(&list_head);

    // Add some elements
    struct my_data node1;
    node1.val = 1;
    list_add_tail(&node1.list, &list_head);

    struct my_data node2;
    node2.val = 2;
    list_add_tail(&node2.list, &list_head);

    struct my_data node3;
    node3.val = 3;
    list_add(&node3.list, &node1.list);

    // Iterate over the list
    // Use `list_for_each_safe` if need to manipulate the linked list in the loop
    struct list_head *p = NULL;
    list_for_each(p, &list_head) {
        struct my_data *entry = list_entry(p, struct my_data, list);
        printk("List element: %d", entry->val);
    }

    // Result: 1 3 2

    // Dynamic version

    struct list_head *dlist_head = kmalloc(sizeof(struct list_head), GFP_KERNEL);
    INIT_LIST_HEAD(dlist_head);
    for (int i = 0; i < 10; ++i) {
        struct my_data *new_node = kmalloc(sizeof(struct my_data), GFP_KERNEL);
        new_node->val            = i;
        list_add(&new_node->list, dlist_head);
    }
    list_for_each(p, dlist_head) {
        struct my_data *entry = list_entry(p, struct my_data, list);
        printk("List element: %d", entry->val);
    }
    // Free
    struct list_head *tmp = NULL;
    list_for_each_safe(p, tmp, dlist_head) {
        struct my_data *entry = list_entry(p, struct my_data, list);
        printk("Removing element: %d", entry->val);
        list_del(p);
        kfree(entry);
    }
    kfree(dlist_head);
    // Result: 9 8 7 6 5 4 3 2 1 0
}
