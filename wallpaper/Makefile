CC=gcc

solution: solution.c
	$(CC) $^ -o $@

wallpaper.o: wallpaper.S
	as $^ -o wallpaper.o

wallpaper: wallpaper.o
	ld -N $^ -o $@
	strip --strip-all $@

all: wallpaper solution

clean: 
	rm solution wallpaper wallpaper.o
