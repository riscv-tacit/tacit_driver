// SPDX-License-Identifier: GPL-2.0
#include <linux/module.h>
#include <linux/of_address.h>
#include <linux/of_pci.h>
#include <linux/of_platform.h>
#include <linux/of_irq.h>
#include <linux/platform_device.h>
#include <linux/init.h>
#include <linux/fs.h>
#include <linux/miscdevice.h>
#include <linux/uaccess.h>
#include <linux/slab.h>
#include <linux/types.h>
#include <linux/idr.h>
#include <linux/printk.h>
#include <linux/device.h>
#include <linux/list.h>
#include <linux/atomic.h>
#include <linux/kernel.h>
#include <linux/string.h>
#include <linux/poll.h>
#include <linux/wait.h>
#include <linux/sched.h>
#include <linux/bitops.h>
#include <linux/sched/task.h>
#include <linux/rhashtable.h>
#include <asm/mmu.h>
#include <trace/events/sched.h>

#define TACIT_NAME "tacit"
#define TR_TE_CTRL 0x0
#define TR_TE_CTRL_ENABLE_OFFSET 1
#define TR_TE_INFO 0x4
#define TR_TE_TARGET 0x20
#define TR_TE_BRANCH_MODE 0x24

#define TRACE_IOC_MAGIC      't'
// --- IOCTL commands ---
#define TRACE_IOC_ENABLE      _IO(TRACE_IOC_MAGIC, 0)
#define TRACE_IOC_DISABLE     _IO(TRACE_IOC_MAGIC, 1)
#define TRACE_IOC_TARGET			_IOW(TRACE_IOC_MAGIC, 2, __u8)

#define TRACE_EXEC
#define TRACE_SCHED_SWITCH

#define DEBUG_TACIT 1

/* Per-instance state */
struct tacit_device {
	struct device *dev;
	void __iomem *enc_base;
	int id; // the hart id 
	struct miscdevice misc;
	bool encoder_enabled;
	struct list_head device_entry;
	struct rhashtable log_table;
	wait_queue_head_t log_wait;
};

struct tacit_log_record {
	// this is the key
	int asid;
	struct rhash_head linkage;
	pid_t pid;
	char comm[TASK_COMM_LEN];
	struct rcu_head rcu_read;
	atomic_t seen_gen;
};

// this is the record that is read by the user
struct tacit_read_record {
	int asid;
	pid_t pid;
	char comm[TASK_COMM_LEN];
};

#define TACIT_BATCH 128
struct tacit_read_ctx {
	struct tacit_device *td; // pointer to the device
	struct rhashtable_iter iter;
	bool iter_inited;
	int gen_id;
	size_t staged; // number of records staged
	struct tacit_read_record batch[TACIT_BATCH];
	bool done; // finished dump
};

static const struct rhashtable_params tacit_log_record_params = {
	.key_len     = sizeof(int),
	.key_offset  = offsetof(struct tacit_log_record, asid),
	.head_offset = offsetof(struct tacit_log_record, linkage),
};

static LIST_HEAD(tacit_devices);
static DEFINE_MUTEX(tacit_devices_lock);

static DEFINE_IDA(traceenc_ida);

static void tacit_encoder_set(struct tacit_device *td, bool enable)
{
	u32 ctrl;
	bool currently_enabled;

	if (!td || !td->enc_base)
		return;

	currently_enabled = READ_ONCE(td->encoder_enabled);
	if (enable == currently_enabled)
		return;

	ctrl = ioread32(td->enc_base + TR_TE_CTRL);
	if (enable)
		ctrl |= BIT(TR_TE_CTRL_ENABLE_OFFSET);
	else
		ctrl &= ~BIT(TR_TE_CTRL_ENABLE_OFFSET);
	iowrite32(ctrl, td->enc_base + TR_TE_CTRL);
	WRITE_ONCE(td->encoder_enabled, enable);
}

static void tacit_log_new_task(struct tacit_device *td, struct task_struct *p)
{
	if (!td || !p || !p->mm)
		return;

	// allocate a new record on the heap
	struct tacit_log_record *record = kmalloc(sizeof(*record), GFP_KERNEL);
	if (!record)
		return;

	record->pid = p->pid;
	int asid = cntx2asid(atomic_long_read(&p->mm->context.id));

	// reject if asid is 0, this is not a user-space task
	if (asid == 0) {
		kfree(record);
		return;
	}

	record->asid = asid;
	atomic_set(&record->seen_gen, 0);
	strscpy(record->comm, p->comm, sizeof(record->comm));

	rhashtable_insert_fast(&td->log_table, &record->linkage, tacit_log_record_params);
}

static ssize_t tacit_read(struct file *file, char __user *buf, size_t len, loff_t *ppos)
{
	struct tacit_read_ctx *ctx = file->private_data;
	struct tacit_device *td = ctx->td;
	size_t out = 0;

	if (!td || !ctx) return -ENODEV;
	if (len < sizeof(struct tacit_read_record)) return -EINVAL;

	/* If we already staged some records from a previous call, flush them first */
	if (ctx->staged) {
		size_t bytes = min(len, ctx->staged * sizeof(ctx->batch[0]));
		size_t cnt   = bytes / sizeof(ctx->batch[0]);
		if (copy_to_user(buf, ctx->batch, cnt * sizeof(ctx->batch[0])))
			return out ? (ssize_t)out : -EFAULT;
		/* shift remaining down */
		memmove(ctx->batch, ctx->batch + cnt, (ctx->staged - cnt) * sizeof(ctx->batch[0]));
		ctx->staged -= cnt;
		return (ssize_t)(cnt * sizeof(ctx->batch[0]));
	}

	/* If dump already completed and nothing staged, EOF */
	if (ctx->done)
		return 0;

	/* Stage up to TACIT_BATCH records under RCU walk */
	if (!ctx->iter_inited) {
		ctx->gen_id++;
		rhashtable_walk_enter(&td->log_table, &ctx->iter);
		ctx->iter_inited = true;
	}
retry_walk:
	rhashtable_walk_start(&ctx->iter);
	while (ctx->staged < TACIT_BATCH) {
		void *obj = rhashtable_walk_next(&ctx->iter);

		if (obj == NULL) {      /* end of table for now */
			ctx->done = true;
			break;
		}
		if (IS_ERR(obj)) {
			if (PTR_ERR(obj) == -EAGAIN) {
				/* table resized; restart this bucket range */
				continue;
			}
			/* unexpected error: stop dump */
			ctx->done = true;
			break;
		}

		/* Got an entry */
		struct tacit_log_record *e = obj;

		/* ensure “once per dump”: mark with gen_id */
		int old = atomic_read(&e->seen_gen);
		if (old == ctx->gen_id)
			continue;
		if (atomic_cmpxchg(&e->seen_gen, old, ctx->gen_id) != old)
			continue;

		/* Stage into kernel buffer (no sleeping ops) */
		ctx->batch[ctx->staged].asid = e->asid;
		ctx->batch[ctx->staged].pid  = e->pid;
		strscpy(ctx->batch[ctx->staged].comm, e->comm, sizeof(ctx->batch[0].comm));
		ctx->staged++;
	}
	rhashtable_walk_stop(&ctx->iter);

	/* If we staged nothing this turn and are not done, the walk hit a resize: try again */
	if (!ctx->staged && !ctx->done)
		goto retry_walk;

	/* Now we are outside RCU; copy staged data to userspace */
	if (ctx->staged) {
		size_t bytes = min(len, ctx->staged * sizeof(ctx->batch[0]));
		size_t cnt   = bytes / sizeof(ctx->batch[0]);
		if (copy_to_user(buf, ctx->batch, cnt * sizeof(ctx->batch[0])))
			return -EFAULT;
		/* shift leftovers down for next read */
		memmove(ctx->batch, ctx->batch + cnt, (ctx->staged - cnt) * sizeof(ctx->batch[0]));
		ctx->staged -= cnt;
		out = cnt * sizeof(ctx->batch[0]);
	}

	/* If we’ve finished the dump and flushed all staged data, clean up the walker */
	if (ctx->done && ctx->staged == 0) {
		rhashtable_walk_exit(&ctx->iter);
		ctx->iter_inited = false;
	}

	/* Nonblocking semantics: if no data produced right now, return -EAGAIN */
	if (out == 0 && (file->f_flags & O_NONBLOCK))
		return -EAGAIN;

	return (ssize_t)out;
}


static __poll_t tacit_poll(struct file *file, poll_table *wait)
{
	struct tacit_read_ctx *ctx = file->private_data;
	struct tacit_device   *td  = ctx->td;
	__poll_t mask = 0;

	/* No real wait source for snapshot dumps; still register something to satisfy poll core */
	poll_wait(file, &td->log_wait, wait);  /* optional: you can keep a dummy waitqueue */

	/* If we still have staged records or the dump isn't finished, it's readable */
	if (ctx && (ctx->staged > 0 || !ctx->done))
		mask |= POLLIN | POLLRDNORM;

	return mask;
}


static struct tacit_device *tacit_dev_get(uint32_t minor)
{
	struct tacit_device *td;
	list_for_each_entry(td, &tacit_devices, device_entry) {
		if (td->misc.minor == minor)
			return td;
	}
	return NULL;
}

/* Open the device */
static int tacit_open(struct inode *inode, struct file *file)
{
	nonseekable_open(inode, file);

	uint32_t minor = iminor(inode);
	struct tacit_device *td = tacit_dev_get(minor);
	if (!td)
		return -ENXIO;
	struct tacit_read_ctx *ctx = kzalloc(sizeof(*ctx), GFP_KERNEL);
	if (!ctx)
		return -ENOMEM;
	ctx->td = td;
	file->private_data = ctx;
	return 0;
}

/* Handle ioctl commands*/
static long tacit_ioctl(struct file *file, unsigned int cmd, unsigned long arg)
{
	struct tacit_read_ctx *ctx = file->private_data;
	struct tacit_device *td = ctx->td;
	if (_IOC_TYPE(cmd) != TRACE_IOC_MAGIC)
		return -ENOTTY;
	switch (cmd) {
	case TRACE_IOC_ENABLE:
		tacit_encoder_set(td, true);
		return 0;
	case TRACE_IOC_DISABLE:
		tacit_encoder_set(td, false);
		return 0;
	case TRACE_IOC_TARGET:
		iowrite32(arg, td->enc_base + TR_TE_TARGET);
		return 0;
	default:
		return -ENOTTY;
	}
}

static int tacit_release(struct inode *inode, struct file *file)
{
	struct tacit_read_ctx *ctx = file->private_data;
	if (ctx) {
		if (ctx->iter_inited) {
			rhashtable_walk_stop(&ctx->iter);
			rhashtable_walk_exit(&ctx->iter);
		}
		kfree(ctx);
	}
	file->private_data = NULL;
	return 0;
}

static const struct file_operations tacit_fops = {
	.owner          = THIS_MODULE,
	.open           = tacit_open,
	.unlocked_ioctl = tacit_ioctl,
	.read           = tacit_read,
	.poll           = tacit_poll,
	.release        = tacit_release,
};

/* Probe the device */
static int tacit_probe(struct platform_device *pdev)
{
	struct tacit_device *td;
	struct device *dev = &pdev->dev;
	struct device_node *node = pdev->dev.of_node;
	struct resource regs;
	int err;

	// Allocate memory for a new device
	td = devm_kzalloc(&pdev->dev, sizeof(*td), GFP_KERNEL);
	if (!td) return -ENOMEM;

	INIT_LIST_HEAD(&td->device_entry);
	mutex_lock(&tacit_devices_lock);
	td->encoder_enabled = false;
		// Allocate an ID for the device
	td->id = ida_simple_get(&traceenc_ida, 0, 0, GFP_KERNEL);
	if (td->id < 0) return td->id;

	init_waitqueue_head(&td->log_wait);
	if (rhashtable_init(&td->log_table, &tacit_log_record_params)) {
		return -ENOMEM;
	}
	
	// Get the register base address
	err = of_address_to_resource(node, 0, &regs);
	if (err) {
		dev_err(dev, "missing \"reg\" property\n");
		return err;
	}
	td->enc_base = devm_ioremap_resource(&pdev->dev, &regs);
	if (IS_ERR(td->enc_base)) return PTR_ERR(td->enc_base);

	// Register a misc device
	td->misc.minor = MISC_DYNAMIC_MINOR;
	td->misc.name = devm_kasprintf(&pdev->dev, GFP_KERNEL, "tacit%d", td->id);
	td->misc.fops = &tacit_fops;
	td->misc.mode = 0660;
	if (misc_register(&td->misc) < 0) {
		dev_err(&pdev->dev, "Failed to register misc device\n");
		return -EBUSY;
	}

	list_add(&td->device_entry, &tacit_devices);
	mutex_unlock(&tacit_devices_lock);


	platform_set_drvdata(pdev, td);
	dev_info(&pdev->dev, "TACIT device registered, minor=%d, id = %d\n", td->misc.minor, td->id);
	return 0;
}

static inline struct tacit_device *tacit_get_device(long cpu)
{
	// iterate over the list of devices
	struct tacit_device *td;
	list_for_each_entry(td, &tacit_devices, device_entry) {
		if (td->id == cpu)
			return td;
	}
	return NULL;
}

#ifdef TRACE_EXEC
static void tacit_on_exec(void *ignore, struct task_struct *p, pid_t old_pid,
	struct linux_binprm *bprm)
{
	int cpu = smp_processor_id();
	struct tacit_device *td = tacit_get_device(cpu);
	if (!td || !p || !p->mm) return;
	if (!td->encoder_enabled) return;
	int asid = cntx2asid(atomic_long_read(&p->mm->context.id));
	if (asid == 0) return;
	if (rhashtable_lookup_fast(&td->log_table, &asid, tacit_log_record_params) != NULL) {
		// pr_err("[TACIT Kernel Driver] asid %d is already registered, pid=%d try will be ignored\n", asid, p->pid);
		return;
	}
	tacit_log_new_task(td, p);
}
#endif

// static void tacit_on_fork(void *ignore, struct task_struct *parent, struct task_struct *child)
// {
// 	int cpu = smp_processor_id();
// 	struct tacit_device *td = tacit_get_device(cpu);
// 	if (!td || !child || !child->mm) return;
// 	if (!td->encoder_enabled) return;
// 	int asid = cntx2asid(atomic_long_read(&child->mm->context.id));
// 	int parent_asid = cntx2asid(atomic_long_read(&parent->mm->context.id));
// 	printk("parent_asid: %d, child_asid: %d\n", parent_asid, asid);
// 	if (asid == 0) return;
// 	if (rhashtable_lookup_fast(&td->log_table, &asid, tacit_log_record_params) != NULL) {
// 		pr_err("[TACIT Kernel Driver] asid %d is already registered, pid=%d try will be ignored\n", asid, child->pid);
// 		return;
// 	}
// 	tacit_log_new_task(td, child);
// }

#ifdef TRACE_SCHED_SWITCH
static void tacit_on_sched_switch(void *ignore,
	bool preempt, struct task_struct *prev, struct task_struct *next, unsigned int prev_state)
{
	int cpu = smp_processor_id();
	struct tacit_device *td = tacit_get_device(cpu);
	if (!td || !next || !next->mm) return;
	if (!td->encoder_enabled) return;
	// check if the asid is registered
	int asid = cntx2asid(atomic_long_read(&next->mm->context.id));
	if (asid == 0) return;
	struct tacit_log_record *record = rhashtable_lookup_fast(&td->log_table, &asid, tacit_log_record_params);
	if (!record) {
		tacit_log_new_task(td, next);
	}
}
#endif

static struct of_device_id tacit_of_match[] = {
	{ .compatible = "ucb-bar,trace" },
	{ .compatible = "ucbbar,trace" },
	{}
};

static struct platform_driver tacit_driver = {
	.driver = {
		.name = TACIT_NAME,
		.of_match_table = tacit_of_match,
		.suppress_bind_attrs = true
	},
	.probe = tacit_probe,
};

static int __init tacit_init(void)
{
	int ret;
	
	#ifdef TRACE_SCHED_SWITCH
	register_trace_sched_switch(tacit_on_sched_switch, NULL);
	#endif
	#ifdef TRACE_EXEC
	register_trace_sched_process_exec(tacit_on_exec, NULL);
	#endif
	// debug check
	if (!trace_sched_process_exec_enabled()) {
		pr_err("[TACIT Kernel Driver] sched_process_exec is not enabled\n");
		return -EINVAL;
	}
	// if (!trace_sched_process_fork_enabled()) {
	// 	pr_err("[TACIT Kernel Driver] sched_process_fork is not enabled\n");
	// 	return -EINVAL;
	// }
	if (!trace_sched_switch_enabled()) {
		pr_err("[TACIT Kernel Driver] sched_switch is not enabled\n");
		return -EINVAL;
	}
	
	ret = platform_driver_register(&tacit_driver);
	if (ret) {
		#ifdef TRACE_SCHED_SWITCH
		unregister_trace_sched_switch(tacit_on_sched_switch, NULL);
		#endif
		#ifdef TRACE_EXEC
		unregister_trace_sched_process_exec(tacit_on_exec, NULL);
		#endif
		return ret;
	}
	
	return 0;
}

static void tacit_log_record_free(void *ptr, void *arg)
{
	kfree(ptr);
}

static void __exit tacit_exit(void)
{
	// iterate over the list of devices
	struct tacit_device *td;
	list_for_each_entry(td, &tacit_devices, device_entry) {
		rhashtable_free_and_destroy(&td->log_table, tacit_log_record_free, NULL);
	}
	platform_driver_unregister(&tacit_driver);
	#ifdef TRACE_SCHED_SWITCH
	unregister_trace_sched_switch(tacit_on_sched_switch, NULL);
	#endif
	#ifdef TRACE_EXEC
	unregister_trace_sched_process_exec(tacit_on_exec, NULL);
	#endif
}

module_init(tacit_init);
module_exit(tacit_exit);
MODULE_DESCRIPTION("Drives the Rocket Chip TACIT Trace Encoder.");
MODULE_LICENSE("Dual BSD/GPL");
MODULE_IMPORT_NS("TRACEPOINTS");
