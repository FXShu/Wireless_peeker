SUBDIRS=utils interface l2_packet crypto interaction pcapng


all:
	for d in $(SUBDIRS); do [ -d $$d ] && $(MAKE) -C $$d;	done
	
clean:
	for d in $(SUBDIRS); do [ -d $$d ] && $(MAKE) -C $$d clean;	done

install:
	for d in $(SUBDIRS); do [ -d $$d ] && $(MAKE) -C $$d install;	done
