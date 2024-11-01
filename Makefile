PROJECT=router
SOURCES=lib/queue.c lib/list.c lib/lib.c router.c lib/routes.c lib/eth.c lib/arp.c lib/ip.c lib/icmp.c lib/packet.c lib/lpm_trie.c lib/debug.c
LIBRARY=nope
INCPATHS=include
LIBPATHS=.
LDFLAGS=
CFLAGS=-c -g -Wall -Werror -Wno-error=unused-variable
CC=gcc

# Automatic generation of some important lists
OBJECTS=$(SOURCES:.c=.o)
INCFLAGS=$(foreach TMP,$(INCPATHS),-I$(TMP))
LIBFLAGS=$(foreach TMP,$(LIBPATHS),-L$(TMP))

# Set up the output file names for the different output types
BINARY=$(PROJECT)

all: $(SOURCES) $(BINARY)

$(BINARY): $(OBJECTS)
	$(CC) $(LIBFLAGS) $(OBJECTS) $(LDFLAGS) -o $@


.c.o:
	$(CC) $(INCFLAGS) $(CFLAGS) -fPIC $< -o $@

clean:
	rm -rf $(OBJECTS) router hosts_output router_* router0 router1

run_router0: all
	./router rtable0.txt rr-0-1 r-0 r-1

run_router1: all
	./router rtable1.txt rr-0-1 r-0 r-1
