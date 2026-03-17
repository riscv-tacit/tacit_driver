ifneq ($(KERNELRELEASE),)

obj-m += tacit.o
tacit-objs := tacit_core.o tacit_dma.o

else

# The default assumes you cloned this as part of firesim-software (FireMarshal)
LINUXSRC=../../../../riscv-linux

KMAKE=make -C $(LINUXSRC) ARCH=riscv CROSS_COMPILE=riscv64-unknown-linux-gnu- M=$(PWD)

tacit.ko: tacit_core.c tacit_dma.c tacit_internal.h
	$(KMAKE)

clean:
	$(KMAKE) clean

endif
