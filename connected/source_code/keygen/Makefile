all: keygen

keygen: ./main.c
	gcc -O2 -march=native -o $@ $^

clean:
	rm -f keygen

.PHONY: clean
