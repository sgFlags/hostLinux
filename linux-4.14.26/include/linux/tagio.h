#ifndef _TAGIO_H
#define _TAGIO_H

#define FLAG_TAG    0x10000

#define GLOBAL_S    50

struct proc_data {
    struct rb_node proc_vt_node;
    struct rb_node proc_pid_node;
    struct list_head list; 
    struct list_head request_list;
    spinlock_t proc_lock;
    pid_t proc_pid;
    u64 proc_disktime;
    uint8_t tag_prio;
};

struct vm_data {
    //struct rb_node vm_vt_node;
    //struct rb_node vm_pid_node;
    struct list_head vm_list;
    pid_t vm_pid;
    u64 vm_disktime;
    spinlock_t procs_vt_lock;
    spinlock_t procs_pid_lock;
    struct rb_root procs_vt_root;
    struct rb_root procs_pid_root;
};

struct noop_data {
	struct list_head queue;
    //struct rb_root vms_vt_root;
    //spinlock_t vms_vt_lock;
    //struct rb_root vms_pid_root;
    //struct idr vms_pid_idr;
    //spinlock_t vms_pid_lock;
    struct list_head vms;
    spinlock_t vms_lock;
};

void insert_proc_into_vt_tree(struct proc_data *procd, struct vm_data *vmd)
{
    struct rb_node **link, *parent;
    struct rb_root *root = &vmd->procs_vt_root;
    u64 value = procd->proc_disktime;

    link = &root->rb_node;
    while (*link) {
        parent = *link;
        struct proc_data *temp_procd = rb_entry(parent, struct proc_data, proc_vt_node);

        if (value < temp_procd->proc_disktime)
            link = &(*link)->rb_left;
        if (value > temp_procd->proc_disktime)
            link = &(*link)->rb_right;
        else {
            list_add_tail(&procd->list, &temp_procd->list);
            return;
        }
    }
    rb_link_node(&procd->proc_vt_node, parent, link);
    rb_insert_color(&procd->proc_vt_node, root);
}

#endif
