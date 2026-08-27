#ifndef TACIT_INTERNAL_H
#define TACIT_INTERNAL_H

#include <linux/types.h>
#include <linux/device.h>
#include <linux/list.h>
#include <linux/miscdevice.h>
#include <linux/rhashtable.h>
#include <linux/wait.h>
#include <linux/mutex.h>
#include <linux/of.h>
#include <linux/dma-mapping.h>
#include <linux/ioctl.h>

#define TACIT_NAME "tacit"

#define TR_TE_CTRL 0x0
#define TR_TE_CTRL_ENABLE_OFFSET 1
#define TR_TE_INFO 0x4
#define TR_TE_TARGET 0x20
#define TR_TE_BRANCH_MODE 0x24
#define TR_TE_STALL_COUNT 0x28

#define TRACE_IOC_MAGIC      't'
#define TRACE_IOC_ENABLE      _IO(TRACE_IOC_MAGIC, 0)
#define TRACE_IOC_DISABLE     _IO(TRACE_IOC_MAGIC, 1)
#define TRACE_IOC_TARGET      _IOW(TRACE_IOC_MAGIC, 2, __u8)
#define TRACE_IOC_STALL_COUNT _IOR(TRACE_IOC_MAGIC, 3, __u64)
#define TRACE_IOC_DMA_COUNT   _IOR(TRACE_IOC_MAGIC, 4, __u64)
#define TRACE_IOC_DMA_WRAP_COUNT _IOR(TRACE_IOC_MAGIC, 5, __u32)
#define TRACE_IOC_DMA_SRC_RDY_STALL_COUNT _IOR(TRACE_IOC_MAGIC, 6, __u32)


#define TARGET_DMA 1

#define TR_SK_DMA_ADDR       0x00
#define TR_SK_DMA_COUNT      0x08
#define TR_SK_DMA_MAX_SIZE   0x10
#define TR_SK_DMA_RESET      0x18
#define TR_SK_DMA_MODE       0x1C
#define TR_SK_DMA_WRAP_COUNT 0x20
#define TR_SK_DMA_SRC_RDY_STALL_COUNT 0x24

#define DMA_MODE_OVERFLOW    0x0
#define DMA_MODE_RING_BUFFER 0x1

struct tacit_dma_dev {
	struct device_node *np;
	void __iomem *base;
	phys_addr_t base_phys;
	void *cpu_addr;
	dma_addr_t dma_addr;
	size_t size;
	u32 mode;
	bool configured;
	struct mutex lock;
};

struct tacit_device {
	struct device *dev;
	void __iomem *enc_base;
	int id;
	struct miscdevice misc;
	bool encoder_enabled;
	struct list_head device_entry;
	struct rhashtable log_table;
	wait_queue_head_t log_wait;
	struct tacit_dma_dev *dma;
};

int tacit_dma_init(struct tacit_device *td, struct device *dev, struct device_node *enc_node);
void tacit_dma_deinit(struct tacit_device *td);
int tacit_dma_prepare_for_target(struct tacit_device *td, u32 target);

#endif
