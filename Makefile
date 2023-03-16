CC=gcc
LIBS=-lcrypto -lm -lgmp
CFLAGS=-I.
DEPS = crypto_tools.h shared_franking.h


%.o: %.c $(DEPS)
		$(CC) -c -o $@ $< $(CFLAGS)

shared_franking_eval: crypto_tools.o shared_franking.o main.o
	$(CC) -o $@ $^ $(CFLAGS) $(LIBS)

plain_franking_eval: crypto_tools.o plain_franking.o
	$(CC) -o $@ $^ $(CFLAGS) $(LIBS)

test: crypto_tools.o shared_franking.o test.o
	$(CC) -o $@ $^ $(CFLAGS) $(LIBS)

.PHONY: clean
clean:
	rm *.o test shared_franking_eval plain_franking_eval
