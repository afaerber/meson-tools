all: amlbootsig

CFLAGS = -g
LDFLAGS = -lcrypto

amlbootsig.o: meson.h fip.h

%.o: %.c
	$(CC) $(CFLAGS) -o $@ -c $<

amlbootsig: amlbootsig.o
	$(CC) $(CFLAGS) $(LDFLAGS) -o $@ $^

clean:
	-rm -f amlbootsig test *.o
