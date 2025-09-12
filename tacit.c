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

#define TACIT_NAME "tacit"

#define TRACE_IOC_MAGIC      't'
#define TRACE_IOC_ENABLE     _IOW(TRACE_IOC_MAGIC, 0, __u32)  /* arg: 1=on, 0=off */
#define TRACE_IOC_DISABLE    _IO(TRACE_IOC_MAGIC, 1)

/* Per-instance state */
struct tacit_device {
	struct device *dev;
	void __iomem *enc_base;
	int id; // the hart 
	struct miscdevice misc;
};

static DEFINE_IDA(traceenc_ida);

/* Open the device */
static int tacit_open(struct inode *inode, struct file *file)
{
	nonseekable_open(inode, file);
	return 0;
}

/* Handle ioctl commands*/
static long tacit_ioctl(struct file *file, unsigned int cmd, unsigned long arg)
{
	// struct tacit_device *td = container_of(file, struct tacit_device, misc);
	u32 val;

	if (_IOC_TYPE(cmd) != TRACE_IOC_MAGIC)
		return -ENOTTY;
	switch (cmd) {
	case TRACE_IOC_ENABLE:
		if (copy_from_user(&val, (void __user *)arg, sizeof(val)))
			return -EFAULT;
		printk(KERN_INFO "TACIT: enabled = %d\n", val);
		return 0;
	case TRACE_IOC_DISABLE:
		printk(KERN_INFO "TACIT: disabled\n");
		return 0;
	default:
		return -ENOTTY;
	}
}

static const struct file_operations tacit_fops = {
	.owner          = THIS_MODULE,
	.open           = tacit_open,
	.unlocked_ioctl = tacit_ioctl,
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

	// Allocate an ID for the device
	td->id = ida_simple_get(&traceenc_ida, 0, 0, GFP_KERNEL);
	if (td->id < 0) return td->id;

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

module_platform_driver(tacit_driver);
MODULE_DESCRIPTION("Drives the Rocket Chip TACIT Trace Encoder.");
MODULE_LICENSE("Dual BSD/GPL");