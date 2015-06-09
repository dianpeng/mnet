all: server.cc client.cc
	g++ -g server.cc ../../mnet.h ../../mnet.cc -o server
	g++ -g client.cc ../../mnet.h ../../mnet.cc -o client

.PHONY: clean

clean:
	rm -r server client
