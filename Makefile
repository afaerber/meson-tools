all: amlbootsig unamlbootsig amlinfo

CFLAGS = -g
LDFLAGS = -lcrypto

amlbootsig.o unamlbootsig.o amlinfo.o: meson.h fip.h

%.o: %.c
	$(CC) $(CFLAGS) -o $@ -c $<

amlbootsig: amlbootsig.o
	$(CC) $(CFLAGS) $(LDFLAGS) -o $@ $^

unamlbootsig: unamlbootsig.o
	$(CC) $(CFLAGS) $(LDFLAGS) -o $@ $^

amlinfo: amlinfo.o
	$(CC) $(CFLAGS) $(LDFLAGS) -o $@ $^

clean:
	-rm -f amlbootsig unamlbootsig amlinfo test *.o
