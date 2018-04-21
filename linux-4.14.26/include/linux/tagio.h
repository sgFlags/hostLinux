#ifndef _TAGIO_H
#define _TAGIO_H

#include <linux/rbtree.c>
#include <linux/spinlock.h>

#define FLAG_TAG    0x10000

#define GLOBAL_S    50

struct tag_data {
    uint8_t prio;
    pid_t vm_pid;
    pid_t proc_pid;
    uint32_t tag_flags;
};

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

void insert_proc_into_vt_tree(struct proc_data *procd, struct vm_data *vmd);

#endif
