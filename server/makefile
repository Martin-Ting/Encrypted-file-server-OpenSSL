EXECUTABLES = server
CXXFLAGS= -ggdb -std=c99 -pedantic-errors
CXX = gcc

all: $(EXECUTABLES)

server: server.c
	$(CXX) $(CXXFLAGS) server.c -l ssl -l crypto -o server

clean:
	rm -f $(OBJECTS) $(EXECUTABLES) *.o *~ 
