main: main.c timer.c synscan.c
	gcc -o portscanner main.c timer.c synscan.c -lpcap -lnet
