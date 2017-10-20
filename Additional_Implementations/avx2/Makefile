# Makefile
# 2017-10-20  Markku-Juhani O. Saarinen <mjos@iki.fi>
# (Additional Implementation: AVX2)

BIN	= genkat_avx2
OBJS	= kem.o hila5_sha3_opt.o ms_ntt_misc.o ms_ntt_const.o ms_x64_ntt.o \
	../../KAT/src/rng.o ../../KAT/src/PQCgenKAT_kem.o

CC	= clang
CFLAGS	= -Wall -Ofast -march=native
LIBS	= -lcrypto
LDFLAGS	=
INCS	= -I.

$(BIN): $(OBJS)
	$(CC) $(LDFLAGS) -o $(BIN) $(OBJS) $(LIBS)

test:	$(BIN)
	./$(BIN)
	@echo "== KAT DIFFERENCE =="
	diff PQCkemKAT_1824.rsp ../../KAT/PQCkemKAT_1824.rsp
	@echo "== CLEANUP =="
	make clean

.S.o:
	$(CC) $(CFLAGS) $(INCS) -c $< -o $@

.c.o:
	$(CC) $(CFLAGS) $(INCS) -c $< -o $@

clean:
	rm -rf $(OBJS) $(BIN) PQCkemKAT_1824.*
