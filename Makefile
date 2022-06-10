all: src/edt2udp.c
	gcc src/edt2udp.c -lpthread -ledt -oedt2udp -Ofast -Wall -march=native
