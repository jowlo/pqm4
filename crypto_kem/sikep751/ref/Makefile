HEADERS = api.h config.h P751_internal.h
SOURCES = ec_isogeny.c fpx.c P751.c sidh.c sike.c generic/fp_generic.c
OBJECTS = P751.o generic/fp_generic.o $(COMMON_OBJS)

pqm4.a: $(OBJECTS)
	$(AR) rcs $@ $(OBJECTS)

%.o: %.c $(HEADERS)
	$(CC) -I$(INCPATH) $(filter-out -pedantic,$(CFLAGS)) -c -o $@ $<

.PHONY: clean

clean:
	-rm -f pqm4.a
	-rm -f *.o

