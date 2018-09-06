SOURCES =          cbd.c owcpa.c poly.c verify.c ntrukem.c
HEADERS = params.h cbd.h owcpa.h poly.h verify.h api.h
OBJECTS =          cbd.o owcpa.o poly.o verify.o ntrukem.o $(COMMON_OBJS)

pqm4.a: $(OBJECTS)
	$(AR) rcs $@ $(OBJECTS)

%.o: %.c $(HEADERS)
	$(CC) -I$(INCPATH) $(CFLAGS) -c -o $@ $<

.PHONY: clean

clean:
	-rm -f pqm4.a
	-rm -f *.o
