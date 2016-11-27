all:util.o callback.o
	gcc -g -o PacketsCapture main.c util.o callback.o -lpcap
util.o:
	gcc -g -c util.c -o util.o  -lpcap
callback.o:
	gcc -g -c callback.c -o callback.o -lpcap
clean:
	rm *.o PacketsCapture