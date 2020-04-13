MKDIR_P = mkdir -p

IDIR=include
PRNG_IDIR=prng/include
MATR_IDIR=matrices/include
CC = gcc
CFLAGS =-Wl,-z,relro,-z,now -Wall -Werror -fstack-protector-all -fpic -I$(IDIR) -I$(PRNG_IDIR) -I$(MATR_IDIR) -shared -s -fvisibility=hidden

TEST_CFLAGS =-Wl,-z,relro,-z,now -Wall -Werror -fstack-protector-all -fpic -I$(IDIR) -I$(PRNG_IDIR) -I$(MATR_IDIR) -s -fvisibility=hidden

ODIR=obj

_DEPS = zkn.h
DEPS = $(patsubst %,$(IDIR)/%,$(_DEPS)) 


_OBJ = zkn.o hash.o
OBJ = $(patsubst %,$(ODIR)/%,$(_OBJ))

PRNG_OBJ=$(ODIR)/prng.o

MOBJ=$(OBJ) $(PRNG_OBJ)

_TEST_OBJ=test.o
TEST_OBJ=$(patsubst %,$(ODIR)/%,$(_TEST_OBJ))

$(ODIR)/%.o: %.c $(DEPS)
	mkdir -p $(@D)
	$(CC) -c -o $@ $< $(CFLAGS)

$(PRNG_OBJ): prng/prng.c $(DEPS)
	mkdir -p $(@D)
	$(CC) -c -o $@ $< $(CFLAGS)
libzkn.so: $(MOBJ)
	$(CC) -o $(ODIR)/$@ $^ $(CFLAGS) $(LIBS)

$(TEST_OBJ): test/test.c
	mkdir -p $(@D)
	$(CC) -c -o $@ $< $(TEST_CFLAGS)	

test_zkn: $(MOBJ) $(TEST_OBJ)
	$(CC) -o $(ODIR)/$@ $^ $(TEST_CFLAGS) $(LIBS)

libzkn: libzkn.so

test: test_zkn

.PHONY: clean 
all: libzkn test
default: all
clean:
	rm -f $(ODIR)/*.o $(ODIR)/libzkn.so $(ODIR)/test_zkn
	rmdir $(ODIR)

