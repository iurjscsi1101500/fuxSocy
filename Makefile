JOBS := $(shell nproc)

obj-m := fuxSocy.o
fuxSocy-objs := main.o file.o net_and_module.o pid.o trace.o

KDIR := /lib/modules/$(shell uname -r)/build
PWD  := $(shell pwd)

ccflags-y += -Wno-missing-declarations -Wno-missing-prototypes

all:
	$(MAKE) -j$(JOBS) -C $(KDIR) M=$(PWD) modules

clean:
	$(MAKE) -C $(KDIR) M=$(PWD) clean

