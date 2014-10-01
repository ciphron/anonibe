CC=gcc
CFLAGS=-O2
LDFLAGS= 
SOURCES=timings.c ag_ibe.c cocks_ibe.c cocks_base.c nua_ibe.c jb_ibe.c
OBJECTS=$(SOURCES:.c=.o)
EXECUTABLE=run
LIBS=-lssl -lm

all: $(EXECUTABLE)

$(EXECUTABLE): $(OBJECTS) 
	$(CC) $(LDFLAGS) $(LIBS) $(OBJECTS) -o $@

.c.o:
	$(CC) $(CFLAGS) -c $< -o $@

clean:
	rm -f *.o $(EXECUTABLE)
