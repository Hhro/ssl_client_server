SRV = ssl_server
CLI = ssl_client
CPP = g++

all: ssl_server.o ssl_client.o
	$(CPP) -o $(SRV) ssl_server.o -L ../lib -lasync -levent -lpthread -lssl -lcrypto
	$(CPP) -o $(CLI) ssl_client.o -L ../lib -lasync -levent -lpthread -lssl -lcrypto

%.o: %.cpp
	$(CPP) -c $< -o $@ -I../include

clean:
	rm *.o $(SRV) $(CLI)
