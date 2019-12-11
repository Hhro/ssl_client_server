CPP = g++
LIB = libasync.a
OBJS = server.o log.o socket.o

$(LIB): $(OBJS)
	$(AR) rv $@ $(OBJS)

%.o: %.cpp
	$(CPP) -c -I../include $< -o $@

clean:
	rm -f $(OBJS) $(LIB)
