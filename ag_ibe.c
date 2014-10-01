/*
    This program is free software: you can redistribute it and/or modify
    it under the terms of the GNU General Public License as published by
    the Free Software Foundation, either version 3 of the License, or
    (at your option) any later version.

    This program is distributed in the hope that it will be useful,
    but WITHOUT ANY WARRANTY; without even the implied warranty of
    MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
    GNU General Public License for more details.

    You should have received a copy of the GNU General Public License
    along with this program.  If not, see <http://www.gnu.org/licenses/>.
*/


#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <openssl/sha.h>
#include <assert.h>

#include "cocks_base.h"
#include "cocks_ibe.h"
#include "ag_ibe.h"

enum {
    L = 6,
    E_PRIME = 20,
    C_SIZE = (L - 1) + E_PRIME,
    MSG_ID_LEN = 20,

    /* 
     * This limit is set to accomodate an implementation detail.
     * Not a restriction of the scheme itself.
     */
    MAX_MSG_BITS = 256 
};

void print_hex(char * s, int len)
{
	int i;
	for (i=0 ; i<len ; i++)
	{
		printf("%02X", 0xff & s[i]);
	}
        printf("\n");
}


void s_xor(uint8_t *dest, const uint8_t *src, size_t len);
void xor_to_elem(BIGNUM *out, const BIGNUM *in, const  uint8_t *h,
                 uint8_t *buf, size_t numbytes);
int T(const BIGNUM * a, const BIGNUM * s, const BIGNUM * N,
      const BIGNUM * four_a, BN_CTX * ctx);

typedef struct rand_pool_t {
    unsigned char bits;
    size_t n_bits;
} rand_pool_t;

void init_rand_pool(rand_pool_t *pool)
{
    pool->n_bits = 0;
}

inline unsigned char rand_bit(rand_pool_t *pool)
{
    unsigned char b;

    if (pool->n_bits == 0) {
        RAND_bytes(&pool->bits, 1);
        pool->n_bits = 8;
    }
    pool->n_bits--;
    b = pool->bits & 1;
    pool->bits >>= 1;

    return b;
}


struct ibe_scheme ag_scheme = {
    ag_master_keygen,
    ag_extract,
    ag_derive_pub_key,
    ag_ciphertext_size,
    ag_encrypt,
    ag_decrypt
};



struct ibe_scheme *ag_get_scheme()
{
    return &ag_scheme;
}

int ag_master_keygen(struct ibe_master_keypair *keypair, size_t len)
{
    return cocks_master_keygen(keypair, len);
}

ibe_sec_key *ag_extract(const ibe_master_key *mk, const ibe_pub_key *pk)
{
    return cocks_extract(mk, pk);
}

ibe_pub_key *ag_derive_pub_key(const ibe_master_param *master_param,
                               const uint8_t *id, size_t id_len)
{
    return cocks_derive_pub_key(master_param, id, id_len);
}



size_t ag_ciphertext_size(const ibe_master_param *master_param,
                          const ibe_pub_key *pk, const uint8_t *message,
                          size_t n_bits)
{
    return (BN_num_bytes((BIGNUM*)master_param) + C_SIZE) *
           2 * n_bits + MSG_ID_LEN;
}

static void encrypt_component(BIGNUM *enc, uint8_t *alphas, const BIGNUM *N,
                              const BIGNUM *a, int bit, int sign, int idx,
                              rand_pool_t *rpool, struct symbols_lst *jacobis, 
                              BN_CTX *ctx, uint8_t *hash_base)
{
    int j;
    int k;
    int m;
    int n;
    unsigned char ok;
    BIGNUM *tmp;
    BIGNUM *candidate;
    const int h_ofs = MSG_ID_LEN + 2;
    const int numbytes = BN_num_bytes(N);
    BIGNUM * four = BN_new();
    BIGNUM * four_a = BN_new();
    unsigned char four_ch[] = {(char)0x04};
    uint8_t * buf = (uint8_t*)calloc(1, numbytes);
    uint8_t *hash = (uint8_t*)malloc(numbytes);

    BN_bin2bn(four_ch, 1, four);
    BN_mod_mul(four_a, a, four, N, ctx);


    tmp = BN_new();
    candidate = BN_new();

    hash_base[MSG_ID_LEN] = (sign == 1) ? 0xFF : 0;
    hash_base[MSG_ID_LEN + 1] = idx & 0xFF;

    cocks_encrypt_bit(jacobis, enc, N, a, bit);

    k = 0;
    while (rand_bit(rpool) == 0) {
        k++;
    }

    if (k < L - 1) {
        m = k;
        hash_base[h_ofs] = k & 0xFF;
        RAND_bytes(&hash_base[h_ofs + 1], 1);
	fdh(hash_base, h_ofs + 2, hash, numbytes);

        xor_to_elem(enc, enc, hash, buf, numbytes);

        alphas[k] = hash_base[h_ofs + 1];
    }
    else
        m = L - 1;

    n = k - (L - 1);
    do {
        RAND_bytes(&alphas[L - 1], E_PRIME);
        ok = 1;

        if (n >= 0) {
            memcpy(&hash_base[h_ofs + 1], &alphas[L - 1], E_PRIME);
            hash_base[h_ofs] = k & 0xFF;
            fdh(hash_base, h_ofs + 1 + E_PRIME, hash, numbytes);

            xor_to_elem(candidate, enc, hash, buf, numbytes);
        }

        for (j = 0; j < n && ok; j++) {
            hash_base[h_ofs] = ((L - 1) + j) & 0xFF;
            fdh(hash_base, h_ofs + 1 + E_PRIME, hash, numbytes);

            xor_to_elem(tmp, candidate, hash, buf, numbytes);
            ok = T(a, tmp, N, four_a, ctx) == -1;
        }

    }
    while (!ok);

    if (n >= 0)
        BN_copy(enc, candidate);
            
    for (j = 0; j < m; j++) {
        do {
            hash_base[h_ofs] = j & 0xFF;
            RAND_bytes(&hash_base[h_ofs + 1], 1);
            fdh(hash_base, h_ofs + 2, hash, numbytes);

            xor_to_elem(tmp, enc, hash, buf, numbytes);

        }
        while (T(a, tmp, N, four_a, ctx) == 1);
        alphas[j] = hash_base[h_ofs + 1];
    }
    
    if (k < L - 2)
        RAND_bytes(&alphas[k + 1], (L - k) - 2);


    BN_free(tmp);
    BN_free(candidate);
    BN_free(four);
    BN_free(four_a);
    free(buf);
    free(hash);

}

static int decrypt_component(const BIGNUM *enc, const uint8_t *alphas,
                             const BIGNUM *N, const BIGNUM *a, const BIGNUM *r,
                             int sign, int idx, BN_CTX *ctx,
                             uint8_t *hash_base)
{
    int j;
    int k;
    int m;
    int n;
    int bit;
    BIGNUM *tmp;
    BIGNUM *candidate;
    const int h_ofs = MSG_ID_LEN + 2;
    const int numbytes = BN_num_bytes(N);
    BIGNUM * four = BN_new();
    BIGNUM * four_a = BN_new();
    unsigned char four_ch[] = {(char)0x04};
    uint8_t * buf = (uint8_t*)calloc(1, numbytes);
    uint8_t *hash = (uint8_t*)malloc(numbytes);

    BN_bin2bn(four_ch, 1, four);
    BN_mod_mul(four_a, a, four, N, ctx);


    tmp = BN_new();
    candidate = BN_new();

    hash_base[MSG_ID_LEN] = (sign == 1) ? 0xFF : 0;
    hash_base[MSG_ID_LEN + 1] = idx & 0xFF;

    k = 0; 
    do {
        hash_base[h_ofs] = k & 0xFF;
        hash_base[h_ofs + 1] = alphas[k];
        fdh(hash_base, h_ofs + 2, hash, numbytes);

        xor_to_elem(tmp, enc, hash, buf, numbytes);
    }
    while (T(a, tmp, N, four_a, ctx) == -1 && ++k < L - 1);

    if (k < L - 1) {
        BN_copy(candidate, tmp);
    }
    else {
        memcpy(&hash_base[h_ofs + 1], &alphas[L - 1], E_PRIME);
        do {
            hash_base[h_ofs] = k & 0xFF;
            fdh(hash_base, h_ofs + 1 + E_PRIME, hash, numbytes);

            xor_to_elem(candidate, enc, hash, buf, numbytes);

            k++;
        }
        while (T(a, candidate, N, four_a, ctx) == -1);
    }


    bit = cocks_decrypt_bit(candidate, r, N);

    BN_free(tmp);
    BN_free(candidate);
    BN_free(four);
    BN_free(four_a);
    free(buf);
    free(hash);

    return bit;
}


int ag_encrypt(const ibe_master_param *master_param, const ibe_pub_key *pk,
               const uint8_t *message, size_t n_bits, uint8_t *ciphertext,
               size_t ct_buf_size)
{
    uint8_t c;
    int i;
    int j;
    int k;
    int m;
    const BIGNUM *N = (const BIGNUM*)master_param;
    BIGNUM *enc;
    size_t nb;
    size_t rem;
    const size_t bytes_per_elem = BN_num_bytes(N);
    struct symbols_lst jacobis;
    const int signs[2] = {1, -1};
    BIGNUM *pubs[2];
    BN_CTX * ctx;
    uint8_t *hash_base;
    rand_pool_t rpool;
    
    
    if (n_bits > MAX_MSG_BITS ||
            ct_buf_size < ag_ciphertext_size(master_param, pk, message, n_bits))
        return -1;

    ctx = BN_CTX_new();
    BN_CTX_start(ctx);

    pubs[0] = (BIGNUM*)pk;
    pubs[1] = BN_new();
    BN_sub(pubs[1], N, pubs[0]);

    enc = BN_new();

    hash_base = (uint8_t*)malloc(MSG_ID_LEN + 1 + 2 + E_PRIME); 
    RAND_bytes(hash_base, MSG_ID_LEN);
    memcpy(ciphertext, hash_base, MSG_ID_LEN);
    ciphertext += MSG_ID_LEN;

    init_jacobis(&jacobis);
    precalc_jacobis(&jacobis, N, n_bits);

    init_rand_pool(&rpool);

    for(i = 0; i < n_bits; i += 8) {
        c = message[i/8];
        for(j = 0; j < 8; j++) {
            for (k = 0; k < 2; k++) {
                encrypt_component(enc, ciphertext + bytes_per_elem, N, pubs[k],
                                  (c & 0x80) ? -1 : 1, signs[k], i + j,
                                  &rpool, &jacobis, ctx, hash_base);

                nb = BN_num_bytes(enc);
                rem = bytes_per_elem - nb;
                while (rem--)
                    *ciphertext++ = 0;
                BN_bn2bin(enc, ciphertext);
                ciphertext += nb + C_SIZE;
            }
            c <<= 1;
        }
    }

    BN_CTX_end(ctx);
    BN_CTX_free(ctx);

    BN_free(pubs[1]);

    free(hash_base);
    BN_free(enc);
    destroy_jacobis(&jacobis);

    return 0;
}


int ag_decrypt(const ibe_master_param *master_param, const ibe_sec_key *sk,
               const uint8_t *ciphertext, size_t ct_size, uint8_t *message,
               size_t msg_buf_size)
{
    const BIGNUM *N = (const BIGNUM*)master_param;
    const struct cocks_ibe_sec_key *c_sk = (const struct cocks_ibe_sec_key*)sk;
    const int sign = id_sign(c_sk->a, c_sk->r, N);
    const int offset = (sign == 1) ? 0 : 1;
    const size_t bytes_per_elem = BN_num_bytes(N);
    size_t n_bits = ct_size / ((bytes_per_elem + C_SIZE) * 2);
    int i;
    int j;
    BIGNUM *enc;
    const uint8_t *alphas;
    uint8_t c;
    const size_t n_bytes = n_bits / 8;
    BN_CTX *ctx;
    uint8_t *hash_base;
    BIGNUM *a;

    if ((n_bits + 7) / 8 < msg_buf_size)
        return -1;

    ctx = BN_CTX_new();
    BN_CTX_start(ctx);

    enc = BN_new();

    a = BN_new();
    if (sign == 1)
        BN_copy(a, c_sk->a);
    else
        BN_sub(a, N, c_sk->a);

    hash_base = (uint8_t*)malloc(MSG_ID_LEN + 1 + 2 + E_PRIME); 
    memcpy(hash_base, ciphertext, MSG_ID_LEN);
    ciphertext += MSG_ID_LEN;

    for (i = 0; i < n_bytes; i++) {
        c = 0;
        for (j = 0; j < 8; j++) {
            c <<= 1;
            BN_bin2bn(ciphertext + offset*(bytes_per_elem + C_SIZE),
                      bytes_per_elem, enc);
            alphas = ciphertext + (offset*(bytes_per_elem + C_SIZE) +
                                   bytes_per_elem);
            c |= (decrypt_component(enc, alphas, N, a, c_sk->r, sign,
                                    i*8 + j, ctx, hash_base) == -1) ? 1 : 0;
            ciphertext += 2*(bytes_per_elem + C_SIZE);
        }
        message[i] = c;
    }

    BN_CTX_end(ctx);
    BN_CTX_free(ctx);

    BN_free(enc);
    BN_free(a);

    return 0;
}

/* returns -1, 1 */
int T(const BIGNUM * a, const BIGNUM * s, const BIGNUM * N,
      const BIGNUM * four_a, BN_CTX * ctx)
{
	int ret;

	BIGNUM * t1;
	BIGNUM * t2;

	t2 = BN_new();
	t1 = BN_new();
	
	BN_mod_sqr(t1, s, N, ctx);
	BN_mod_sub(t2, t1, four_a, N, ctx);
	
	ret = BN_kronecker(t2, N, ctx);
	
	BN_free(t1);
	BN_free(t2);

	return ret;
}

/* calculates dest = dest xor src 
 * dest and src must be of the same length in bytes */

inline void s_xor(uint8_t *dest, const uint8_t *src, size_t len)
{
	int i;
	for (i=0; i<len; i++)
		dest[i] ^= src[i];
}

inline void xor_to_elem(BIGNUM *out, const BIGNUM *in, const  uint8_t *h,
                        uint8_t *buf, size_t numbytes)
{
    buf[0] = buf[1] = 0;
    BN_bn2bin(in, buf + (numbytes - BN_num_bytes(in)));
    s_xor(buf, h, numbytes);
    BN_bin2bn(buf, numbytes, out);

}
