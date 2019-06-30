all: amlbootsig unamlbootsig amlbootsig-gxl amlbootenc-gxl amlinfo

CFLAGS = -g
LDFLAGS = -lcrypto

amlbootsig.o unamlbootsig.o amlinfo.o: meson.h aml.h fip.h
amlbootsig-gxl.o amlbootenc-gxl.o: meson.h aml.h

%.o: %.c
	$(CC) $(CFLAGS) -o $@ -c $<

amlbootsig: amlbootsig.o
	$(CC) $(CFLAGS) -o $@ $^ $(LDFLAGS)

unamlbootsig: unamlbootsig.o
	$(CC) $(CFLAGS) -o $@ $^ $(LDFLAGS)

amlbootsig-gxl: amlbootsig-gxl.o
	$(CC) $(CFLAGS) -o $@ $^ $(LDFLAGS)

amlbootenc-gxl: amlbootenc-gxl.o
	$(CC) $(CFLAGS) -o $@ $^ $(LDFLAGS)

amlinfo: amlinfo.o
	$(CC) $(CFLAGS) -o $@ $^ $(LDFLAGS)

clean:
	-rm -f amlbootsig unamlbootsig amlbootsig-gxl amlinfo test *.o
