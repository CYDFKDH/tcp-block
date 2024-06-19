tcp-block: main.c
	 gcc -o tcp-block main.c -lpcap

clean:
	rm -f tcp-block
