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


/* cocks-ibe.c */
/* Written by Paolo Gasti, 2008 (gasti@disi.unige.it)
 * Extended by Michael Clear, 2013 (clearm@scss.tcd.ie)
 */
 
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <openssl/sha.h>
#include <assert.h>

#include "cocks_base.h"
#include "cocks_ibe.h"


struct ibe_scheme cocks_scheme = {
    cocks_master_keygen,
    cocks_extract,
    cocks_derive_pub_key,
    cocks_ciphertext_size,
    cocks_encrypt,
    cocks_decrypt
};

struct ibe_scheme *cocks_get_scheme()
{
    return &cocks_scheme;
}

int cocks_master_keygen(struct ibe_master_keypair *keypair, size_t len)
{
    struct cocks_master_key *mk = (struct cocks_master_key*)malloc(sizeof(struct cocks_master_key));
    int ret;

    ret = masterkeygen(mk, len);

    if (ret < 0)
        free(mk);
    else {
        BN_CTX *ctx;
        BIGNUM *N;

        ctx = BN_CTX_new();
        N = BN_new();

	BN_mul(N, mk->p, mk->q, ctx);
        keypair->master_param = (ibe_master_param*)N;
        keypair->master_key = (ibe_master_key*)mk;

        BN_CTX_free(ctx);
    }

    return ret;
}

ibe_sec_key *cocks_extract(const ibe_master_key *mk, const ibe_pub_key *pk)
{
    struct cocks_ibe_sec_key *sk = (struct cocks_ibe_sec_key*)malloc(sizeof(struct cocks_ibe_sec_key));
    const struct cocks_master_key *c_mk = (const struct cocks_master_key*)mk;

    sk->a = BN_new();
    sk->r = BN_new();

    BN_copy(sk->a, (BIGNUM*)pk);
    extract(sk->r, c_mk->p, c_mk->q, sk->a);

    return (ibe_sec_key*)sk;
}

ibe_pub_key *cocks_derive_pub_key(const ibe_master_param *master_param, const uint8_t *id,
                                  size_t id_len)
{
    BIGNUM *a = BN_new();

    getkey(a, id, id_len, (const BIGNUM*)master_param);

    return (ibe_pub_key*)a;
}



size_t cocks_ciphertext_size(const ibe_master_param *master_param, const ibe_pub_key *pk,
                             const uint8_t *message, size_t n_bits)
{
    return BN_num_bytes((BIGNUM*)master_param) * 2 * n_bits;
}

int cocks_encrypt(const ibe_master_param *master_param, const ibe_pub_key *pk,
                  const uint8_t *message, size_t n_bits, uint8_t *ciphertext,
                  size_t ct_buf_size)
{
    uint8_t c;
    int i;
    int j;
    int k;
    BIGNUM *N = (BIGNUM*)master_param;
    BIGNUM *enc;
    size_t nb;
    size_t rem;
    const size_t bytes_per_elem = BN_num_bytes(N);
    struct symbols_lst jacobis;
    BIGNUM *pubs[2];
    
    if (ct_buf_size < bytes_per_elem * 2 * n_bits)
        return -1;

    pubs[0] = (BIGNUM*)pk;
    pubs[1] = BN_new();
    BN_sub(pubs[1], N, pubs[0]);

    enc = BN_new();

    init_jacobis(&jacobis);
    precalc_jacobis(&jacobis, N, n_bits);

    for(i = 0; i < n_bits; i += 8) {
        c = message[i/8];
        for(j = 0; j < 8; j++) {
            for (k = 0; k < 2; k++) {
                cocks_encrypt_bit(&jacobis, enc, N, pubs[k],
                                  (c & 0x80) ? -1 : 1);
                nb = BN_num_bytes(enc);
                rem = bytes_per_elem - nb;
                while (rem--)
                    *ciphertext++ = 0;
                BN_bn2bin(enc, ciphertext);
                ciphertext += nb;
            }
            c <<= 1;
        }
    }

    BN_free(pubs[1]);
    BN_free(enc);
    destroy_jacobis(&jacobis);

    return 0;
}


int cocks_decrypt(const ibe_master_param *master_param, const ibe_sec_key *sk,
                  const uint8_t *ciphertext, size_t ct_size, uint8_t *message,
                  size_t msg_buf_size)
{
    BIGNUM *N = (BIGNUM*)master_param;
    const struct cocks_ibe_sec_key *c_sk = (const struct cocks_ibe_sec_key*)sk;
    int offset = (id_sign(c_sk->a, c_sk->r, N) == 1) ? 0 : 1;
    const size_t bytes_per_elem = BN_num_bytes(N);
    size_t n_bits = ct_size / (bytes_per_elem * 2);
    int i;
    int j;
    BIGNUM *enc;
    uint8_t c;
    const size_t n_bytes = n_bits / 8;

    if ((n_bits + 7) / 8 < msg_buf_size)
        return -1;

    enc = BN_new();

    for (i = 0; i < n_bytes; i++) {
        c = 0;
        for (j = 0; j < 8; j++) {
            c <<= 1;
            BN_bin2bn(ciphertext + ((i*8 + j)*2 + offset)*bytes_per_elem,
                      bytes_per_elem, enc);
            c |= (cocks_decrypt_bit(enc, c_sk->r, N) == 1) ? 0 : 1;
        }
        message[i] = c;
    }

    BN_free(enc);
    return 0;
}

