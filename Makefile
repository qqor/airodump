LDLIBS=-lpcap

all: airodump

airodump: airodump.o
	$(LINK.cc) $^ $(LOADLIBES) $(LDLIBS) -o $@

clean:
	rm -f airodump *.o