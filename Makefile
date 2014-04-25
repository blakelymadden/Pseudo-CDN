default: all

all: exec_scripts
	gcc -o dnsserver dnsserver.c

exec_scripts:
	chmod +x deployCDN runCDN stopCDN httpserver

clean:
	rm -f *~ *.pyc *.o dnsserver
