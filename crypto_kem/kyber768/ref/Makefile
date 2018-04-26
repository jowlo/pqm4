HEADERS = api.h cbd.h indcpa.h ntt.h params.h poly.h polyvec.h reduce.h verify.h
SOURCES = cbd.c indcpa.c kem.c ntt.c poly.c polyvec.c precomp.c reduce.c verify.c
OBJECTS = cbd.o indcpa.o kem.o ntt.o poly.o polyvec.o precomp.o reduce.o verify.o $(COMMON_OBJS)

pqlib.a: $(OBJECTS)
	$(AR) rcs $@ $(OBJECTS)

%.o: %.c $(HEADERS)
	$(CC) -I$(INCPATH) $(CFLAGS) -c -o $@ $<

.PHONY: clean

clean:
	-rm -f pqlib.a
	-rm -f *.o
