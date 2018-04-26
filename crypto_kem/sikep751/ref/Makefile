HEADERS = api.h config.h P751_internal.h
SOURCES = ec_isogeny.c fpx.c P751.c sidh.c sike.c generic/fp_generic.c
OBJECTS = P751.o generic/fp_generic.o $(COMMON_OBJS)

pqlib.a: $(OBJECTS)
	$(AR) rcs $@ $(OBJECTS)

%.o: %.c $(HEADERS)
	$(CC) -I$(INCPATH) $(CFLAGS) -c -o $@ $<

.PHONY: clean

clean:
	-rm -f pqlib.a
	-rm -f *.o

