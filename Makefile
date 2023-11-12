SUBDIRS = user kernel
# SUBDIRS = user

.PHONY:all install clean


all:
	@for subdir in $(SUBDIRS); do\
		$(MAKE) -C $$subdir; \
	done


install:
	@for subdir in $(SUBDIRS); do\
		$(MAKE) -C $$subdir install; \
	done

clean:
	@for subdir in $(SUBDIRS); do\
		$(MAKE) -C $$subdir clean; \
	done
