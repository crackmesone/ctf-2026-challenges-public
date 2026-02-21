BIN=connected

CXX=g++
CXXFLAGS=-O1 -DNDEBUG -std=c++23 -mtune=generic -masm=intel -I./include -Wall
LDFLAGS=

all: $(BIN)

$(BIN): $(patsubst %.cpp,%.o,$(wildcard ./src/*.cpp))
	$(CXX) $(CXXFLAGS) -o $@ $^

.o: %.c
	$(CXX) $(CXXFLAGS) -c -o $@ $^

install:
	cp ./$(BIN) $(DESTDIR)$(PREFIX)/bin/

uninstall:
	rm -f $(DESTDIR)$(PREFIX)/bin/$(BIN)

clean:
	rm -f ./$(BIN) ./src/*.o *.o

.PHONY: clean
