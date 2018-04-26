HEADERS = api.h config.h frodo_macrify.h 
OBJECTS = frodo640.o  util.o $(COMMON_OBJS)


pqlib.a: $(OBJECTS)
	$(AR) rcs $@ $(OBJECTS)
	@cp pqlib.a $(BINDIR)



%.o: %.c $(HEADERS)
	$(CC) -I$(INCPATH) $(CFLAGS) -c -o $@ $<

.PHONY: clean

clean:
	-rm -f pqlib.a
	-rm -f *.o
