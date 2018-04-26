HEADERS = api.h config.h frodo_macrify.h 
OBJECTS = frodo640.o kem.o noise.o util.o $(COMMON_OBJS)




pqlib.a: $(OBJECTS)
	$(AR) rcs $@ $(OBJECTS)


%.o: %.c $(HEADERS)
	$(CC) -I$(INCPATH) $(CFLAGS) -c -o $@ $<

.PHONY: clean

clean:
	-rm -f pqlib.a
	-rm -f *.o
