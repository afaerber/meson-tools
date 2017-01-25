all: amlbootsig amlinfo

CFLAGS = -g
LDFLAGS = -lcrypto

amlbootsig.o amlinfo.o: meson.h fip.h

%.o: %.c
	$(CC) $(CFLAGS) -o $@ -c $<

amlbootsig: amlbootsig.o
	$(CC) $(CFLAGS) $(LDFLAGS) -o $@ $^

amlinfo: amlinfo.o
	$(CC) $(CFLAGS) $(LDFLAGS) -o $@ $^

clean:
	-rm -f amlbootsig amlinfo test *.o
