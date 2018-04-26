OBJECTS = dec.o enc.o int32_sort.o keypair.o r3_mult.o r3_recip.o random32.o randomsmall.o randomweightw.o rq.o rq_mult.o rq_recip3.o rq_round3.o rq_rounded.o small.o swap.o crypto_hashblocks_sha512.o crypto_hash_sha512.o crypto_verify_32.o $(COMMON_OBJS)
HEADERS = api.h crypto_kem.h crypto_kem_sntrup4591761.h int32_sort.h mod3.h modq.h params.h r3.h randomweightw.c rq.h small.h swap.h crypto_verify_32.h crypto_hashblocks_sha512.h crypto_hash_sha512.h


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
