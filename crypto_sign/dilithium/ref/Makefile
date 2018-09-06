OBJECTS = sign.o polyvec.o packing.o poly.o reduce.o ntt.o rounding.o $(COMMON_OBJS)
HEADERS = api.h params.h sign.h polyvec.h packing.h poly.h reduce.h ntt.h \
  rounding.h


pqm4.a: $(OBJECTS)
	$(AR) rcs $@ $(OBJECTS)


%.o: %.c $(HEADERS)
	$(CC) -I$(INCPATH) $(CFLAGS) -c -o $@ $<

.PHONY: clean

clean:
	-rm -f pqm4.a
	-rm -f *.o 
