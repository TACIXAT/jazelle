obj-m := hwkm.o
hwkm-objs := asm-lkm-wrapper.o asm-lkm.o 

all:
	as -o asm-lkm.o asm-lkm.s
	make -C /lib/modules/4.9.59+/build M=$(PWD)
clean:
	rm *.o *.ko
