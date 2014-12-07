EXECUTABLES = client 
CXXFLAGS= -ggdb -std=c99 -pedantic-errors
CXX = gcc

all: $(EXECUTABLES)

client: client.c
	$(CXX) $(CXXFLAGS) client.c -l ssl -l crypto -o client

clean:
	rm -f $(OBJECTS) $(EXECUTABLES) *.o *~ 
