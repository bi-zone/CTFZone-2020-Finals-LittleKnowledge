MKDIR_P = mkdir -p

IDIR=include
CC = gcc
CFLAGS =-Wl,-z,relro,-z,now -Wall -Werror -fpic -I$(IDIR) -shared


ODIR=obj

_DEPS = zkn.h
DEPS = $(patsubst %,$(IDIR)/%,$(_DEPS))

_OBJ = zkn.o
OBJ = $(patsubst %,$(ODIR)/%,$(_OBJ))

$(ODIR)/%.o: %.c $(DEPS)
	mkdir -p $(@D)
	$(CC) -c -o $@ $< $(CFLAGS)

libzkn.so: $(OBJ)
	$(CC) -o $(ODIR)/$@ $^ $(CFLAGS) $(LIBS)

libzkn: libzkn.so


.PHONY: clean 
all: libzkn
default: all
clean:
	rm -f $(ODIR)/*.o $(ODIR)/libzkn.so
	rmdir $(ODIR)

