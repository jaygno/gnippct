all: tcpping

uninstall: remove

INCLUDE= -I./libpcap-1.7.4  -I./libnet-master/
STATIC_LIB = ./libnet-master/libs/libnet.a ./libpcap-1.7.4/libs/libpcap.a
tcpping: tcpping.c
	$(CC) -Wall -g tcpping.c -o tcpping $(CFLAGS) $(INCLUDE) ${STATIC_LIB} -L/lib64  -ldbus-1 

install:
	install -m 4755 ./tcpping /usr/bin/tcpping

remove:
	rm -f /usr/bin/tcpping

clean:
	rm -f ./tcpping
