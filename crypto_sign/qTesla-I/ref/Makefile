OBJECTS= sign.o consts.o sample.o poly.o $(COMMON_OBJS)
HEADERS= api.h params.h sample.h poly.h


pqm4.a: $(OBJECTS)
	$(AR) rcs $@ $(OBJECTS)


%.o: %.c $(HEADERS)
	$(CC) -I$(INCPATH) $(CFLAGS) -c -o $@ $<

.PHONY: clean

clean:
	-rm -f pqm4.a
	-rm -f *.o

