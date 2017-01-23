all: test

test: test.c
	$(CC) -g -o $@ -lcrypto test.c

clean:
	-rm -f test

