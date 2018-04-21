/*
 * elevator noop
 */
#include <linux/blkdev.h>
#include <linux/elevator.h>
#include <linux/bio.h>
#include <linux/module.h>
#include <linux/slab.h>
#include <linux/init.h>
#include <linux/idr.h>
#include <linux/tagio.h>

void insert_proc_into_vt_tree(struct proc_data *procd, struct vm_data *vmd)
{
    struct rb_node **link, *parent = NULL;
    struct rb_root *root = &vmd->procs_vt_root;
    struct proc_data *temp_procd;
    u64 value = procd->proc_disktime;

    link = &root->rb_node;
    while (*link) {
        parent = *link;
        temp_procd = rb_entry(parent, struct proc_data, proc_vt_node);

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
    printk(KERN_ERR"insert_proc_into_vt_tree finished for proc %u\n", procd->proc_pid);
}

static void noop_merged_requests(struct request_queue *q, struct request *rq,
				 struct request *next)
{
	list_del_init(&next->queuelist);
}

static int noop_dispatch(struct request_queue *q, int force)
{
	struct noop_data *nd = q->elevator->elevator_data;
	struct request *rq;
    struct vm_data *vmd, *temp_vmd;
    struct proc_data *procd, *next_procd;
    struct rb_node *node;
    int tag_ok = FLAG_TAG + FLAG_OK;
    u64 min_disktime;
    u64 stride;

    /* find the vm with smallest vm_disktime */
    
    vmd = list_first_entry_or_null(&nd->vms, struct vm_data, vm_list);
    
    if (!vmd) {
        goto my_fail;
    }
    min_disktime = vmd->vm_disktime;
    list_for_each_entry(temp_vmd, &nd->vms, vm_list) {
         if (temp_vmd->vm_disktime < min_disktime) {
            vmd = temp_vmd;
            min_disktime = vmd->vm_disktime;
         }
    }

    /* find the process with smallest proc_disktime */
    node = rb_first(&vmd->procs_vt_root);
    procd = rb_entry(node, struct proc_data, proc_vt_node);
    printk(KERN_ERR "proc %u is going to be dispatched! before procd->proc_lock\n", procd->proc_pid);
    if (list_empty(&procd->request_list)) {
        printk(KERN_ERR "strange!!\n");
        goto my_fail;
    }
    rq = list_last_entry(&procd->request_list, struct request, tag_list);
   
    if (rq == NULL) {
        printk(KERN_ERR"rq is null??\n");
        goto my_fail;
    }

    stride = GLOBAL_S / rq->tag_prio;
   
    procd->proc_disktime += stride;
    vmd->vm_disktime += stride;
    
    //printk(KERN_ERR"before delete tag_list\n");

    //list_del_init(&rq->queuelist);
    //printk(KERN_ERR"after delete tag_list\n");
    
    if (!list_empty(&procd->list)) {
        printk(KERN_ERR"same vt has more than one procs!\n");
        next_procd = list_first_entry(&procd->list, struct proc_data, list);
        list_del(&procd->list);
        rb_replace_node(&procd->proc_vt_node, &next_procd->proc_vt_node, &vmd->procs_vt_root);
    } else {
        rb_erase(&procd->proc_vt_node, &vmd->procs_vt_root);
    }
    
    if (list_empty(&procd->request_list)) {
        //printk(KERN_ERR"about to delete procd! it is %u\n", procd->proc_pid);
        insert_proc_into_vt_tree(procd, vmd);
        printk(KERN_ERR"proc %u doesn't have any requests, but still insert this proc back\n", procd->proc_pid);
    } else {
        insert_proc_into_vt_tree(procd, vmd);
        printk(KERN_ERR"proc %u still has requests, insert this proc back\n", procd->proc_pid);
    }

    //list_del_init(&rq->queuelist);
	//list_add_tail(&rq->queuelist, &nd->queue);

my_fail:
	rq = list_first_entry_or_null(&nd->queue, struct request, queuelist);
	if (rq) {
		list_del_init(&rq->queuelist);
		elv_dispatch_sort(q, rq);
		return 1;
	}
	return 0;
}
static void noop_add_request(struct request_queue *q, struct request *rq)
{
	struct noop_data *nd = q->elevator->elevator_data;
    //if (rq->tagio.tag_flags == FLAG_TAG) {
    //}
      //  return;
    list_add_tail(&rq->queuelist, &nd->queue);
}

static struct request *
noop_former_request(struct request_queue *q, struct request *rq)
{
	struct noop_data *nd = q->elevator->elevator_data;

	if (rq->queuelist.prev == &nd->queue)
		return NULL;
	return list_prev_entry(rq, queuelist);
}

static struct request *
noop_latter_request(struct request_queue *q, struct request *rq)
{
	struct noop_data *nd = q->elevator->elevator_data;

	if (rq->queuelist.next == &nd->queue)
		return NULL;
	return list_next_entry(rq, queuelist);
}

/* e6998 */
static int noop_set_request(struct request_queue *q, struct request *rq, struct bio *bio, gfp_t gfp_mask)
{
    //printk("in noop_set_request!\n");
    struct noop_data *nd = q->elevator->elevator_data;
    struct vm_data *vmd, *backup_vmd;
    struct proc_data *procd, *backup_procd; 
    struct rb_node **link;
    struct rb_node *parent = NULL;
    bool find = false;
    u64 min_disktime;

    if (!bio || bio->tag_flags != FLAG_TAG)
        return 0;

    backup_vmd = kmalloc(sizeof(struct vm_data), gfp_mask);
    backup_procd = kmalloc(sizeof(struct proc_data), gfp_mask);

    spin_lock_irq(q->queue_lock);

    rq->tag_prio = bio->tag_prio;
    rq->tagio.vm_pid = bio->vm_pid;
    rq->tagio.proc_pid = bio->proc_pid;
    rq->tagio.tag_flags = bio->tag_flags;
    printk(KERN_ERR "request enter noop set, prio is %u, pid is %u, vm_pid is %u, tag_flags is %u\n", rq->tag_prio, rq->tagio.proc_pid, rq->tagio.vm_pid, rq->tagio.tag_flags);

    if (!backup_vmd)
        printk(KERN_ERR "out of memory\n");
    backup_vmd->procs_vt_root = RB_ROOT;
    backup_vmd->procs_pid_root = RB_ROOT;
   
    if (!backup_procd)
        printk(KERN_ERR "out of memory\n");
    backup_procd->tag_prio = rq->tag_prio;
    spin_lock_init(&backup_procd->proc_lock);
    /* set the vm this request belongs to */
    //spin_lock_irq(&nd->vms_lock);
    
    /* initialize min_disktime for vm */
    vmd = list_first_entry_or_null(&nd->vms, struct vm_data, vm_list);
    if (vmd)
        min_disktime = vmd->vm_disktime;
    else
        min_disktime = 0;
    list_for_each_entry(vmd, &nd->vms, vm_list) {
        if (vmd->vm_disktime < min_disktime)
            min_disktime = vmd->vm_disktime;
        if (rq->tagio.vm_pid == vmd->vm_pid) {
            find = true;
            rq->tagio.vmdata = vmd;
            printk(KERN_ERR"find vm for this request, vm is %u\n", vmd->vm_pid);
            break;
        }
    } 
    
    /* try to find the vmd */ 
    if (!find) {
        vmd = backup_vmd;
        vmd->vm_pid = rq->tagio.vm_pid;
        vmd->vm_disktime = min_disktime;
        spin_lock_init(&vmd->procs_vt_lock);
        spin_lock_init(&vmd->procs_pid_lock);
        rq->tagio.vmdata = vmd;
        list_add(&vmd->vm_list, &nd->vms);
        printk(KERN_ERR"not find vm for this request, init this vm, vm is %u\n", vmd->vm_pid);
    } else {
        kfree(backup_vmd);
    }
    //spin_unlock_irq(&nd->vms_lock);
    
    find = false;
    /* find the process this request belongs to */
    //spin_lock_irq(&vmd->procs_pid_lock);
    if (RB_EMPTY_ROOT(&vmd->procs_vt_root) || RB_EMPTY_ROOT(&vmd->procs_pid_root))
        min_disktime = 0;
    else
        min_disktime = rb_entry(rb_first(&vmd->procs_vt_root), struct proc_data, proc_vt_node)->proc_disktime;
   
    link = &vmd->procs_pid_root.rb_node;
    while (*link) {
        parent = *link;
        procd = rb_entry(parent, struct proc_data, proc_pid_node);

        if (rq->tagio.proc_pid < procd->proc_pid)
            link = &(*link)->rb_left;
        else if (rq->tagio.proc_pid > procd->proc_pid)
            link = &(*link)->rb_right;
        else {
            printk(KERN_ERR"find proc for this request, proc_pid is %u\n", procd->proc_pid);
            find = true;
            rq->tagio.procdata = procd;
            break;
        }
    }
    if (!find) {
        procd = backup_procd; 
        rq->tagio.procdata = procd;
        procd->proc_pid = rq->tagio.proc_pid;
        procd->proc_disktime = min_disktime;
        procd->tag_prio = rq->tag_prio;
        INIT_LIST_HEAD(&procd->list);
        INIT_LIST_HEAD(&procd->request_list);
        rb_link_node(&procd->proc_pid_node, parent, link);
        rb_insert_color(&procd->proc_pid_node, &vmd->procs_pid_root);
        printk(KERN_ERR "not find this proc, newly init a proc, after rb_insert_color, proc pid is %d\n", procd->proc_pid);
        //spin_lock(&procd->proc_lock);
        //spin_lock(&vmd->procs_vt_lock);
        insert_proc_into_vt_tree(procd, vmd);
        //spin_unlock(&vmd->procs_vt_lock);
        //spin_unlock(&procd->proc_lock);
    } else {
        kfree(backup_procd);
    }
    //spin_unlock_irq(&vmd->procs_pid_lock);

    //spin_lock_irq(&procd->proc_lock);
    //list_del_init(&rq->queuelist);
    //list_add(&rq->queuelist, &procd->request_list);
    list_add(&rq->tag_list, &procd->request_list);
    //spin_unlock_irq(&procd->proc_lock);
    spin_unlock_irq(q->queue_lock);
    return 0;
}

static int noop_init_queue(struct request_queue *q, struct elevator_type *e)
{
	struct noop_data *nd;
	struct elevator_queue *eq;

	eq = elevator_alloc(q, e);
	if (!eq)
		return -ENOMEM;

	nd = kmalloc_node(sizeof(*nd), GFP_KERNEL, q->node);
	if (!nd) {
		kobject_put(&eq->kobj);
		return -ENOMEM;
	}
	eq->elevator_data = nd;

	INIT_LIST_HEAD(&nd->queue);

    /* e6998 */
    //nd->vms_vt_root = RB_ROOT;
    //nd->vms_pid_root = RB_ROOT;
    //spin_lock_init(&nd->vms_vt_lock);
    //spin_lock_init(&nd->vms_pid_lock);
    spin_lock_init(&nd->vms_lock);
    INIT_LIST_HEAD(&nd->vms);

	spin_lock_irq(q->queue_lock);
	q->elevator = eq;
	spin_unlock_irq(q->queue_lock);
	return 0;
}

static void noop_exit_queue(struct elevator_queue *e)
{
	struct noop_data *nd = e->elevator_data;

	BUG_ON(!list_empty(&nd->queue));
	kfree(nd);
}

static struct elevator_type elevator_noop = {
	.ops.sq = {
		.elevator_merge_req_fn		= noop_merged_requests,
		.elevator_dispatch_fn		= noop_dispatch,
		.elevator_add_req_fn		= noop_add_request,
		.elevator_former_req_fn		= noop_former_request,
		.elevator_latter_req_fn		= noop_latter_request,
        .elevator_set_req_fn    = noop_set_request,
		.elevator_init_fn		= noop_init_queue,
		.elevator_exit_fn		= noop_exit_queue,
	},
	.elevator_name = "noop",
	.elevator_owner = THIS_MODULE,
};

static int __init noop_init(void)
{
	return elv_register(&elevator_noop);
}

static void __exit noop_exit(void)
{
	elv_unregister(&elevator_noop);
}

module_init(noop_init);
module_exit(noop_exit);


MODULE_AUTHOR("Jens Axboe");
MODULE_LICENSE("GPL");
MODULE_DESCRIPTION("No-op IO scheduler");
