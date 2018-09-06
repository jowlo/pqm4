HEADERS = api.h config.h frodo_macrify.h 
OBJECTS = frodo640.o  util.o $(COMMON_OBJS)


pqm4.a: $(OBJECTS)
	$(AR) rcs $@ $(OBJECTS)
	@cp pqm4.a $(BINDIR)



%.o: %.c $(HEADERS)
	$(CC) -I$(INCPATH) $(CFLAGS) -c -o $@ $<

.PHONY: clean

clean:
	-rm -f pqm4.a
	-rm -f *.o
