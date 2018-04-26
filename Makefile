# KEMLIBS=$(wildcard crypto_kem/*/*)
# SIGNLIBS=$(wildcard crypto_sign/*/*)

OWNDIR=$(shell pwd)
INCPATH=$(OWNDIR)/common

OBJS        = $(OWNDIR)/obj/fips202.o 
RANDOMBYTES = $(OWNDIR)/obj/randombytes.o

COMMON_OBJS=$(OBJS) $(RANDOMBYTES)

CFLAGS += $(INCLUDES) -I$(OWNDIR)/


export INCPATH
export COMMON_OBJS

all: tests testvectors speeds stack

.PHONY: force


ifneq ($(origin PQ_KEM), undefined)
KEMLIB=crypto_kem/$(PQ_KEM)
LIBS=$(OWNDIR)/$(KEMLIB)/pqlib.a
endif
ifneq ($(origin PQ_SIGN), undefined)
SIGNLIB=crypto_sign/$(PQ_SIGN)
LIBS+=$(OWNDIR)/$(SIGNLIB)/pqlib.a
endif


libs: $(COMMON_OBJS) $(KEMLIB) $(SIGNLIB) force
ifeq ($(words $(LIBS)), 1)
	@cp $(LIBS) $(BINDIR)/pqlib.a
else
	ar -rcT $(BINDIR)/pqlib.a $(LIBS)
endif

tests: libs $(KEMTESTS) $(SIGNTESTS)
testvectors: libs $(KEMTESTVECTORS) $(SIGNTESTVECTORS)
speeds: libs $(KEMSPEEDS) $(SIGNSPEEDS)
stack: libs $(KEMSTACK) $(SIGNSTACK)


$(KEMLIB): force 
	make -C $@

$(SIGNLIB): force
	make -C $@

$(OWNDIR)/obj/randombytes.o: $(OWNDIR)/common/randombytes.c
	mkdir -p obj 
	$(CC) $(CFLAGS) -o $@ -c $^
	@cp $@ $(BINDIR)


$(OWNDIR)/obj/fips202.o:  $(OWNDIR)/common/fips202.c
	mkdir -p obj 
	$(CC) $(CFLAGS) -o $@ -c $^
	@cp $@ $(BINDIR)


.PHONY: clean 

clean:
	find . -name \*.o -type f -exec rm -f {} \;
	find . -name \*.d -type f -exec rm -f {} \;
	find crypto_kem -name \*.a -type f -exec rm -f {} \;
	find crypto_sign -name \*.a -type f -exec rm -f {} \;
	rm -rf elf/
	rm -rf bin/
	rm -rf obj/
	rm -rf testvectors/
	rm -rf benchmarks/
