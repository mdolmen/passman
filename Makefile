# Notes :
#       -> $@ : current target
#       -> $^ : dependency list
#       -> $< : first dependency

CC=gcc
LD=gcc
BIN=bin
SRC=src
INCLUDE=include
TEST=test

NACL_INCLUDE=-I /usr/include/nacl/
NACL_LIB=-lnacl -lstdc++

# TODO : split debug flags to another var
CFLAGS=-g -Wall -I $(INCLUDE) -Llib $(NACL_INCLUDE) $(NACL_LIB)

LDFLAGS=

passman: $(SRC)/passman.o $(SRC)/io.o $(SRC)/utils.o
	mkdir bin && $(LD) $(LDFLAGS) -o $(BIN)/$@ $^ $(CFLAGS)

test: $(TEST)/test.o $(SRC)/io.o
	$(LD) $(LDFLAGS) -o $(TEST)/$@ $^ $(CFLAGS)


passman.o: $(SRC)/passman.c $(INCLUDE)/passman.h
	$(CC) -c $< $(CFLAGS)

io.o: $(SRC)/io.c $(INCLUDE)/io.h
	$(CC) -c $< $(CFLAGS)

utils.o: $(SRC)/utils.o $(INLCUDE)/utils.h
	$(CC) -c $< $(CFLAGS)

test.o : $(TEST)/test.c $(INCLUDE)/io.h
	$(CC) -c $< $(CFLAGS)


clean:
	rm -f $(SRC)/*.o
