# Notes :
#       -> $@ : current target
#       -> $^ : dependency list
#       -> $< : first dependency

CC=gcc
LD=gcc
BIN=bin
SRC=src
INCLUDE=include
TEST=tests

# FLAGS
# -----

TEST_FLAGS=-lcheck
NACL_INCLUDE=-I /usr/include/nacl/
NACL_LIB=-lnacl -lstdc++

CFLAGS=-Wall -Wextra -Wformat-security -Wno-unused-result -fstack-protector -D_FORTIFY_SOURCE=2 -O2 -fPIE -I $(INCLUDE) -Llib $(NACL_INCLUDE) $(NACL_LIB)

LDFLAGS=-z relro


# TARGETS
# -------

passman: $(SRC)/passman.o $(SRC)/io.o $(SRC)/utils.o
	$(LD) $(LDFLAGS) -o $(BIN)/$@ $^ $(CFLAGS)

test: $(TEST)/test.o $(SRC)/io.o $(SRC)/utils.o
	$(LD) $(LDFLAGS) -o $(TEST)/$@ $^ $(CFLAGS) $(TEST_FLAGS)


passman.o: $(SRC)/passman.c $(INCLUDE)/passman.h
	$(CC) -c $< $(CFLAGS)

io.o: $(SRC)/io.c $(INCLUDE)/io.h $(INCLUDE)/utils.h
	$(CC) -c $< $(CFLAGS)

utils.o: $(SRC)/utils.o $(INLCUDE)/utils.h
	$(CC) -c $< $(CFLAGS)

test.o : $(TEST)/test.c $(INCLUDE)/io.h
	$(CC) -c $< $(CFLAGS) $(TEST_FLAGS)


clean:
	rm -f $(SRC)/*.o $(TEST)/*.o
