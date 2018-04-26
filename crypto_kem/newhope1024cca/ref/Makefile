OBJECTS= poly.o ntt.o cpapke.o kem.o precomp.o reduce.o verify.o $(COMMON_OBJS)
HEADERS= api.h cpapke.h ntt.h params.h poly.h reduce.h verify.h 


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
