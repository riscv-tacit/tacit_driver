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
#include <trace/events/sched.h>

#define TACIT_NAME "tacit"
#define TR_TE_CTRL 0x0
#define TR_TE_CTRL_ENABLE_OFFSET 1
#define TR_TE_INFO 0x4
#define TR_TE_TARGET 0x20
#define TR_TE_BRANCH_MODE 0x24

#define TRACE_IOC_MAGIC      't'
// --- IOCTL commands ---
// Enable the trace encoder
#define TRACE_IOC_ENABLE     _IO(TRACE_IOC_MAGIC, 0)
// Disable the trace encoder
#define TRACE_IOC_DISABLE    _IO(TRACE_IOC_MAGIC, 1)
// Watch for the current PID
#define TRACE_IOC_WATCH_PID  _IO(TRACE_IOC_MAGIC, 2)

static LIST_HEAD(tacit_devices);
static DEFINE_MUTEX(tacit_devices_lock);

static DEFINE_IDA(traceenc_ida);

/* Per-instance state */
struct tacit_device {
	struct device *dev;
	void __iomem *enc_base;
	int id; // the hart 
	struct miscdevice misc;
	struct list_head device_entry;
	pid_t watch_pid;
};

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
	file->private_data = td;
	return 0;
}

/* Handle ioctl commands*/
static long tacit_ioctl(struct file *file, unsigned int cmd, unsigned long arg)
{
	struct tacit_device *td = file->private_data;
	uint32_t curr;
	if (_IOC_TYPE(cmd) != TRACE_IOC_MAGIC)
		return -ENOTTY;
	switch (cmd) {
	case TRACE_IOC_ENABLE:
		curr = ioread32(td->enc_base + TR_TE_CTRL);
		iowrite32(curr | 0x1 << TR_TE_CTRL_ENABLE_OFFSET, td->enc_base + TR_TE_CTRL);
		pr_info("[TACIT Kernel Driver] Enabled trace encoder\n");
		return 0;
	case TRACE_IOC_DISABLE:
		curr = ioread32(td->enc_base + TR_TE_CTRL);
		iowrite32(curr & ~(0x1 << TR_TE_CTRL_ENABLE_OFFSET), td->enc_base + TR_TE_CTRL);
		pr_info("[TACIT Kernel Driver] Disabled trace encoder\n");
		return 0;
	case TRACE_IOC_WATCH_PID:
		td->watch_pid = task_pid_nr(current);
		pr_info("[TACIT Kernel Driver] Watching for pid %d\n", td->watch_pid);
		return 0;
	default:
		return -ENOTTY;
	}
}

static int tacit_release(struct inode *inode, struct file *file)
{
	file->private_data = NULL;
	return 0;
}

static const struct file_operations tacit_fops = {
	.owner          = THIS_MODULE,
	.open           = tacit_open,
	.unlocked_ioctl = tacit_ioctl,
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
	list_add(&td->device_entry, &tacit_devices);
	mutex_unlock(&tacit_devices_lock);

	// Allocate an ID for the device
	td->id = ida_simple_get(&traceenc_ida, 0, 0, GFP_KERNEL);
	if (td->id < 0) return td->id;

	// initialize the watch_pid
	td->watch_pid = -1;

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

static void tacit_on_exec(void *ignore, struct task_struct *p, pid_t old_pid,
	struct linux_binprm *bprm)
{
	int cpu = smp_processor_id();
	struct tacit_device *td = tacit_get_device(cpu);
	if (!td) return;
	if (p->pid == td->watch_pid) {
		pr_info("[TACIT Kernel Driver] Process %s (PID %d) has been execed\n", p->comm, p->pid);
	}
}

static void tacit_on_sched_switch(void *ignore,
	bool preempt, struct task_struct *prev, struct task_struct *next, unsigned int prev_state)
{
	int cpu = smp_processor_id();
	struct tacit_device *td = tacit_get_device(cpu);
	if (!td) return;
	if (next->pid == td->watch_pid) {
		pr_info("[TACIT Kernel Driver] Process %s (PID %d) has been scheduled\n", next->comm, next->pid);
	}
}

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
	
	register_trace_sched_switch(tacit_on_sched_switch, NULL);
	register_trace_sched_process_exec(tacit_on_exec, NULL);
	// check if sched_switch and sched_process_exec is enabled
	if (!trace_sched_process_exec_enabled()) {
		pr_err("[TACIT Kernel Driver] sched_process_exec is not enabled\n");
		return -EINVAL;
	}
	if (!trace_sched_switch_enabled()) {
		pr_err("[TACIT Kernel Driver] sched_switch is not enabled\n");
		return -EINVAL;
	}
	
	ret = platform_driver_register(&tacit_driver);
	if (ret) {
		unregister_trace_sched_switch(tacit_on_sched_switch, NULL);
		unregister_trace_sched_process_exec(tacit_on_exec, NULL);
		return ret;
	}
	
	return 0;
}

static void __exit tacit_exit(void)
{
	platform_driver_unregister(&tacit_driver);
	unregister_trace_sched_switch(tacit_on_sched_switch, NULL);
	unregister_trace_sched_process_exec(tacit_on_exec, NULL);
}

module_init(tacit_init);
module_exit(tacit_exit);
MODULE_DESCRIPTION("Drives the Rocket Chip TACIT Trace Encoder.");
MODULE_LICENSE("Dual BSD/GPL");
MODULE_IMPORT_NS("TRACEPOINTS");
