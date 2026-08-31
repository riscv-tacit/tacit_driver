// SPDX-License-Identifier: GPL-2.0
#include <linux/slab.h>
#include <linux/errno.h>
#include <linux/of_address.h>
#include <linux/io.h>
#include <linux/sizes.h>
#include <linux/dma-mapping.h>

#include "tacit_internal.h"

/* Internal-only DMA staging buffer size. */
#define TACIT_DMA_DEFAULT_SIZE SZ_4M

/* 0 = overflow (default: the first buffer-full is a decodable trace prefix,
 * extractable with FireSim's +dumpmem), 1 = ring (keeps the newest window,
 * sustains backpressure forever, but wraps destroy decodability). */
static int dma_mode = 0;
module_param(dma_mode, int, 0444);
MODULE_PARM_DESC(dma_mode, "trace DMA sink mode: 0=overflow, 1=ring");

/* Buffer size in MiB. >4 requires CONFIG_DMA_CMA (contiguous alloc); pass
 * tacit.dma_size_mb=N on the kernel cmdline. Size it to hold the whole trace
 * so the overflow-mode prefix is the complete stream. */
static int dma_size_mb = 4;
module_param(dma_size_mb, int, 0444);
MODULE_PARM_DESC(dma_size_mb, "trace DMA buffer size in MiB (default 4)");

static int tacit_dma_hw_reset(struct tacit_dma_dev *d)
{
	if (!d || !d->base)
		return -ENODEV;

	/* Reset register is pulsed via write-1 semantics. */
	iowrite32(1, d->base + TR_SK_DMA_RESET);
	return 0;
}

static int tacit_dma_program(struct tacit_device *td)
{
	struct tacit_dma_dev *d = td ? td->dma : NULL;
	int ret;

	if (!td || !d || !d->base || !d->cpu_addr)
		return -ENODEV;

	mutex_lock(&d->lock);

	ret = tacit_dma_hw_reset(d);
	if (ret) {
		mutex_unlock(&d->lock);
		return ret;
	}

	writeq((u64)d->dma_addr, d->base + TR_SK_DMA_ADDR);
	writeq((u64)d->size, d->base + TR_SK_DMA_MAX_SIZE);
	// writeq(0, d->base + TR_SK_DMA_MAX_SIZE);
	// printk("debug: forcing immediate overflow");
	iowrite32(d->mode, d->base + TR_SK_DMA_MODE);

	wmb();

	d->configured = true;
	mutex_unlock(&d->lock);
	return 0;
}

int tacit_dma_init(struct tacit_device *td, struct device *dev, struct device_node *enc_node)
{
	struct tacit_dma_dev *d;
	struct device_node *dma_np;
	struct resource dma_res;
	int ret;

	if (!td)
		return -EINVAL;

	dma_np = of_parse_phandle(enc_node, "ucbbar,trace-dma", 0);
	if (!dma_np) {
		dev_info(dev, "trace-dma phandle missing; DMA target unavailable\n");
		td->dma = NULL;
		return 0;
	}

	d = devm_kzalloc(dev, sizeof(*d), GFP_KERNEL);
	if (!d) {
		of_node_put(dma_np);
		return -ENOMEM;
	}

	d->np = dma_np;
	mutex_init(&d->lock);
	d->mode = dma_mode ? DMA_MODE_RING_BUFFER : DMA_MODE_OVERFLOW;
	d->configured = false;

	ret = of_address_to_resource(dma_np, 0, &dma_res);
	if (ret) {
		dev_err(dev, "failed to parse trace-dma reg resource: %d\n", ret);
		of_node_put(dma_np);
		return ret;
	}

	d->base_phys = dma_res.start;
	d->base = devm_ioremap_resource(dev, &dma_res);
	if (IS_ERR(d->base)) {
		ret = PTR_ERR(d->base);
		dev_err(dev, "failed to map trace-dma MMIO: %d\n", ret);
		of_node_put(dma_np);
		return ret;
	}

	ret = dma_set_mask_and_coherent(dev, DMA_BIT_MASK(64));
	if (ret) {
		dev_err(dev, "dma_set_mask_and_coherent failed: %d\n", ret);
		of_node_put(dma_np);
		return ret;
	}

	d->size = (dma_size_mb > 0) ? ((size_t)dma_size_mb << 20) : TACIT_DMA_DEFAULT_SIZE;
	d->cpu_addr = dma_alloc_coherent(dev, d->size, &d->dma_addr, GFP_KERNEL);
	if (!d->cpu_addr) {
		dev_err(dev, "dma_alloc_coherent failed for %zu bytes\n", d->size);
		of_node_put(dma_np);
		return -ENOMEM;
	}

	td->dma = d;
	phys_addr_t cpu_phys = virt_to_phys(d->cpu_addr);

	dev_info(dev, "trace-dma: dma_addr=%pad size=%zu\n", &d->dma_addr, d->size);
	dev_info(dev, "trace-dma: cpu_addr=%p cpu_phys=%pa\n", d->cpu_addr, &cpu_phys);
	dev_info(dev, "trace-dma: mmio_base=%p\n", d->base);
	
	return 0;
}

void tacit_dma_deinit(struct tacit_device *td)
{
	struct tacit_dma_dev *d;

	if (!td || !td->dma)
		return;

	d = td->dma;
	if (d->cpu_addr) {
		dma_free_coherent(td->dev, d->size, d->cpu_addr, d->dma_addr);
		d->cpu_addr = NULL;
	}
	if (d->np) {
		of_node_put(d->np);
		d->np = NULL;
	}

	td->dma = NULL;
}

int tacit_dma_prepare_for_target(struct tacit_device *td, u32 target)
{
	int ret;

	if (!td)
		return -EINVAL;

	if (target != TARGET_DMA)
		return 0;

	if (!td->dma || !td->dma->base || !td->dma->cpu_addr) {
		dev_err(td->dev, "target DMA requested but dma is not ready\n");
		return -ENODEV;
	}

	ret = tacit_dma_program(td);
	if (ret)
		dev_err(td->dev, "failed to program trace-dma target: %d\n", ret);
	return ret;
}
