// hila5.h
// 2017-09-09  Markku-Juhani O. Saarinen <mjos@iki.fi>

#ifndef _HILA5_H_
#define _HILA5_H_

#include <stdint.h>

#define HILA5_N         1024
#define HILA5_Q         12289
#define HILA5_B         799
#define HILA5_MAX_ITER  100
#define HILA5_SEED_LEN  32
#define HILA5_KEY_LEN   32
#define HILA5_ECC_LEN   30
#define HILA5_PACKED1   (HILA5_N / 8)
#define HILA5_PACKED14  (14 * HILA5_N / 8)
#define HILA5_PAYLOAD_LEN (HILA5_KEY_LEN + HILA5_ECC_LEN)

#define HILA5_PUBKEY_LEN (HILA5_SEED_LEN + HILA5_PACKED14)
#define HILA5_PRIVKEY_LEN (HILA5_PACKED14 + 32)

#define HILA5_CIPHERTEXT_LEN (HILA5_PACKED14 + HILA5_PACKED1 + \
    HILA5_PAYLOAD_LEN + HILA5_ECC_LEN)

// == KEM FUNCTION PROTOTYPES ==

// key generation
int hila5_keygen(   uint8_t pk[HILA5_PUBKEY_LEN],
                    uint8_t sk[HILA5_PRIVKEY_LEN]);

// encapsulate
int hila5_encaps(   uint8_t ct[HILA5_CIPHERTEXT_LEN],
                    uint8_t ss[HILA5_KEY_LEN],
                    const uint8_t pk[HILA5_PUBKEY_LEN]);

// decapsulate
int hila5_decaps(   uint8_t ss[HILA5_KEY_LEN],
                    const uint8_t ct[HILA5_CIPHERTEXT_LEN],
                    const uint8_t sk[HILA5_PRIVKEY_LEN]);

#endif

