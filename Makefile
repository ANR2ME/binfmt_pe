obj-m	+= src/binfmt_pe.o
src/binfmt_pe-objs	:= src/pe.o

KDIR    := /lib/modules/$(shell uname -r)/build
PWD     := $(shell pwd)

all:
	$(MAKE) -C $(KDIR) SUBDIRS=$(PWD) modules

clean:
	rm -f $(PWD)/modules.order $(PWD)/Module.symvers
	$(MAKE) -C $(KDIR) M=$(PWD) clean          
