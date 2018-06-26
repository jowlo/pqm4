COMMON_OBJS ?= ../../../common/fips202.o ../../../common/randombytes.o 
INCPATH += ../../../common/

HEADERS = api.h cbd.h kem.h pack_unpack.h poly.h poly_mul.h recon.h SABER_indcpa.h SABER_params.h verify.h
SOURCES = cbd.c kem.c pack_unpack.c poly.c poly_mul.c recon.c SABER_indcpa.c verify.c
OBJECTS = cbd.o kem.o pack_unpack.o poly.o poly_mul.o recon.o SABER_indcpa.o verify.o $(COMMON_OBJS)

libpq.a: $(OBJECTS)
	$(AR) rcs $@ $(OBJECTS)

%.o: %.c $(HEADERS)
	$(CC) -shared -I$(INCPATH) $(CFLAGS) -c -o $@ $<

.PHONY: clean

clean:
	-rm -f libpqm4.a
	-rm -f *.o
