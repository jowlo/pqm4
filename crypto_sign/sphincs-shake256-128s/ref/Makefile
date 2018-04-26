HEADERS = params.h hash.h          hash_address.h wots.h utils.h fors.h api.h
OBJECTS =          hash_shake256.o hash_address.o wots.o utils.o fors.o sign.o $(COMMON_OBJS)

pqlib.a: $(OBJECTS)
	$(AR) rcs $@ $(OBJECTS)

%.o: %.c $(HEADERS)
	$(CC) -I$(INCPATH) $(CFLAGS) -c -o $@ $<

.PHONY: clean

clean:
	-rm -f libpqm4.a
	-rm -f *.o
