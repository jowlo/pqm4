OBJECTS = core.o fft_transform.o gen_randomness.o kem.o poly.o poly_encode.o $(COMMON_OBJS)
HEADERS = api.h core.h gen_randomness.h params.h poly.h


pqlib.a: $(OBJECTS)
	$(AR) rcs $@ $(OBJECTS)
	@cp pqlib.a $(BINDIR)


%.o: %.c $(HEADERS)
	$(CC) -I$(INCPATH) $(CFLAGS) -c -o $@ $<

%.o: %.S $(HEADERS)
	$(CC) -I$(INCPATH) $(CFLAGS) -c -o $@ $<


.PHONY: clean

clean:
	-rm pqlib.a
	-rm *.o 
