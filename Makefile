# KEMLIBS=$(wildcard crypto_kem/*/*)
# SIGNLIBS=$(wildcard crypto_sign/*/*)

OWNDIR=$(shell pwd)

ifneq ($(origin PQ_COMMON_IMPL), undefined)
	INCPATH			= $(OWNDIR)/common/$(PQ_COMMON_IMPL)/
	ifneq (,$(filter "m4" "m0", "$(PQ_COMMON_IMPL)"))
		KECCAK_SRC	= $(OWNDIR)/common/$(PQ_COMMON_IMPL)/keccakf1600.S
		FIPS202_SRC = $(OWNDIR)/common/$(PQ_COMMON_IMPL)/fips202.c
	endif
else
	INCPATH			= $(OWNDIR)/common/generic/
	KECCAK_SRC	= $(OWNDIR)/common/generic/keccakf1600.c
	FIPS202_SRC = $(OWNDIR)/common/generic/fips202.c
endif

COMMON_OBJS = $(OWNDIR)/obj/keccakf1600.o $(OWNDIR)/obj/fips202.o $(OWNDIR)/obj/randombytes.o

CFLAGS += $(INCLUDES) -I$(OWNDIR)/


export INCPATH
export COMMON_OBJS

all: tests testvectors speeds stack

.PHONY: force


ifneq ($(origin PQ_KEM), undefined)
KEMLIB=crypto_kem/$(PQ_KEM)/$(PQ_KEM_IMPL)
LIBS=$(OWNDIR)/$(KEMLIB)/pqm4.a
endif
ifneq ($(origin PQ_SIGN), undefined)
SIGNLIB=crypto_sign/$(PQ_SIGN)/$(PQ_SIGN_IMPL)
LIBS+=$(OWNDIR)/$(SIGNLIB)/pqm4.a
endif


define DEPENDABLE_VAR

.PHONY: phony
$1: phony
	@if [[ `cat $1 2>&1` != '$($1)' ]]; then \
		echo -n $($1) > $1 ; \
	fi
endef

#declare scheme selections to be dependable
$(eval $(call DEPENDABLE_VAR,KEMLIB))
$(eval $(call DEPENDABLE_VAR,SIGNLIB))

libs: $(COMMON_OBJS) $(KEMLIB) $(SIGNLIB) KEMLIB SIGNLIB
ifeq ($(words $(LIBS)), 1)
	@cp $(LIBS) $(BINDIR)/pqm4.a
else
	ar -rcT $(BINDIR)/pqm4.a $(LIBS)
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


$(OWNDIR)/obj/fips202.o:  $(FIPS202_SRC)
	mkdir -p obj 
	$(CC) $(CFLAGS) -o $@ -c $^
	@cp $@ $(BINDIR)


$(OWNDIR)/obj/keccakf1600.o:  $(KECCAK_SRC)
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
