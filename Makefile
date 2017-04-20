all: amlbootsig unamlbootsig amlinfo

CFLAGS = -g
LDFLAGS = -lcrypto

amlbootsig.o unamlbootsig.o amlinfo.o: meson.h fip.h

%.o: %.c
	$(CC) $(CFLAGS) -o $@ -c $<

amlbootsig: amlbootsig.o
	$(CC) $(CFLAGS) -o $@ $^ $(LDFLAGS)

unamlbootsig: unamlbootsig.o
	$(CC) $(CFLAGS) -o $@ $^ $(LDFLAGS)

amlinfo: amlinfo.o
	$(CC) $(CFLAGS) -o $@ $^ $(LDFLAGS)

clean:
	-rm -f amlbootsig unamlbootsig amlinfo test *.o
