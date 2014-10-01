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
#include <openssl/bn.h>
#include <assert.h>

#include "cocks_base.h"
#include "cocks_ibe.h"
#include "nua_ibe.h"


struct nua_ibe_pub_key {
    BIGNUM *a;
    BIGNUM * const *g;
};

struct nua_ibe_sec_key {
    BIGNUM *a;
    BIGNUM * const *g;
    BIGNUM *r;
};

struct ibe_scheme nua_scheme = {
    nua_master_keygen,
    nua_extract,
    nua_derive_pub_key,
    nua_ciphertext_size,
    nua_encrypt,
    nua_decrypt
};


BIGNUM **poly_new()
{
    BIGNUM **p = (BIGNUM**)malloc(2 * sizeof(BIGNUM*));
    int i;
    
    for (i = 0; i < 2; i++)
        p[i] = BN_new();

    return p;
}

void poly_free(BIGNUM ** p)
{   
    int i;

    for (i = 0; i < 2; i++)
        BN_free(p[i]);

    free(p);
}

int poly_mul(BIGNUM **z, BIGNUM * const *x, BIGNUM * const *y,
             const BIGNUM *a, const BIGNUM *m, BN_CTX *ctx)
{
    BIGNUM *t1 = BN_new();
    BIGNUM *t2 = BN_new();
    BIGNUM *t3 = BN_new();

    /* Compute z[0] */
    BN_mod_mul(t1, x[0], y[0], m, ctx);
    BN_mod_mul(t2, x[1], y[1], m, ctx);
    BN_mod_mul(t3, t2, a, m, ctx);
    BN_mod_add(z[0], t1, t3, m, ctx);

    /* Compute z[1] */
    BN_mod_mul(t1, x[0], y[1], m, ctx);
    BN_mod_mul(t2, x[1], y[0], m, ctx);
    BN_mod_add(z[1], t1, t2, m, ctx);

    BN_free(t1);
    BN_free(t2);
    BN_free(t3);

    return 0;
}

/* Galbraith's test in ZZ[x]/(x^2 - a) */
int gt(const BIGNUM *a, BIGNUM * const *f, const BIGNUM *N, BN_CTX *ctx)
{
    BIGNUM *t1 = BN_new();
    BIGNUM *t2 = BN_new();
    BIGNUM *t3 = BN_new();
    BIGNUM *t4 = BN_new();
    int gt_v;


    BN_mod_sqr(t1, f[0], N, ctx);
    BN_mod_sqr(t2, f[1], N, ctx);
    BN_mod_mul(t3, t2, a, N, ctx);

    BN_mod_sub(t4, t1, t3, N, ctx);

    gt_v = BN_kronecker(t4, N, ctx);

    BN_free(t1);
    BN_free(t2);
    BN_free(t3);
    BN_free(t4);


    return gt_v;
}





struct ibe_scheme *nua_get_scheme()
{
    return &nua_scheme;
}

int nua_master_keygen(struct ibe_master_keypair *keypair, size_t len)
{
    return cocks_master_keygen(keypair, len);
}

ibe_sec_key *nua_extract(const ibe_master_key *mk, const ibe_pub_key *pk)
{
    struct nua_ibe_sec_key *sk = 
        (struct nua_ibe_sec_key*)malloc(sizeof(struct nua_ibe_sec_key));
    const struct nua_ibe_pub_key *n_pk = (const struct nua_ibe_pub_key*)pk;
    const struct cocks_ibe_sec_key *c_sk;

    sk->g = poly_new();
    BN_copy(sk->g[0], n_pk->g[0]);
    BN_copy(sk->g[1], n_pk->g[1]);

    c_sk = (const struct cocks_ibe_sec_key*)cocks_extract(mk, (const ibe_pub_key*)(n_pk->a));
    sk->a = c_sk->a;
    sk->r = c_sk->r;

    return (ibe_sec_key*)sk;
}

/*
 * This could be done more efficiently by storing an integer x with Jacobi 
 * symbol -1 as part of the master parameters, as mentioned in Boneh, Gentry
 * and Hamburg (2007) - http://www.stanford.edu/~dabo/papers/bgh.pdf.
 */
ibe_pub_key *nua_derive_pub_key(const ibe_master_param *master_param, const uint8_t *id,
                                size_t id_len)
{
    const BIGNUM *N = (const BIGNUM*)master_param;
    BIGNUM *am;
    const int num_bytes = BN_num_bytes(N) - 1;
    BN_CTX *ctx;
    struct nua_ibe_pub_key *pk = 
        (struct nua_ibe_pub_key*)malloc(sizeof(struct nua_ibe_pub_key));
    const size_t digest_size = 20;
    uint8_t hash[digest_size];
    uint8_t *buf = (uint8_t*)malloc(num_bytes);

    ctx = BN_CTX_new();
    BN_CTX_start(ctx);

    pk->a = BN_new();
    pk->g = poly_new();

    fdh(id, id_len, buf, num_bytes);
    BN_bin2bn(buf, num_bytes, pk->a);
    while (BN_kronecker(pk->a, N, ctx) != 1) {
        memcpy(hash, buf, digest_size);
        fdh(hash, digest_size, buf, num_bytes);
        BN_bin2bn(buf, num_bytes, pk->a);
    }
    am = BN_new();
    BN_sub(am, N, pk->a);

    do {
        memcpy(hash, buf, digest_size);
        fdh(hash, digest_size, buf, num_bytes);
        BN_bin2bn(buf, num_bytes, pk->g[0]);

        memcpy(hash, buf, digest_size);
        fdh(hash, digest_size, buf, num_bytes);
        BN_bin2bn(buf, num_bytes, pk->g[1]);
    }
    while (gt(pk->a, pk->g, N, ctx) == 1 || gt(am, pk->g, N, ctx) == 1);

    BN_free(am); 

    BN_CTX_end(ctx);
    BN_CTX_free(ctx);
    free(buf);


    return (ibe_pub_key*)pk;
}



size_t nua_ciphertext_size(const ibe_master_param *master_param, const ibe_pub_key *pk,
                           const uint8_t *message, size_t n_bits)
{
    return BN_num_bytes((const BIGNUM*)master_param) * 4 * n_bits;
}


static int encrypt_component(BIGNUM **enc, const BIGNUM *N, const BIGNUM *a,
                             BIGNUM * const *g, int bit, int coin,
                             struct symbols_lst *jacobis, BN_CTX *ctx)
{
    BIGNUM *t; 
    BIGNUM *it;
    BIGNUM *two;
    BIGNUM *h;
    BIGNUM *hsqr;
    BIGNUM *tmp[2];

   
    if(bit != 1 && bit != -1)
        return -1;

    two = BN_new();
    BN_bin2bn((unsigned char *)"\x2", 1, two);

    /*if(get_jacobi(jacobis, &t, &it, bit) == 2) {
        precalc_jacobis(jacobis, N, 1);
        get_jacobi(jacobis, &t, &it, bit);
        }*/
    get_jacobi(jacobis, &t, &it, bit, N, ctx);

    h = BN_new();
    hsqr = BN_new();
    BN_rand(h, BN_num_bits(N), -1, 0);
    BN_mod_sqr(hsqr, h, N, ctx);
    BN_mod_mul(enc[0], a, hsqr, N, ctx);

    tmp[0] = BN_new();
    tmp[1] = BN_new();

    BN_mod_mul(tmp[1], enc[0], it, N, ctx);
    BN_mod_add(enc[0], tmp[1], t, N, ctx);
    BN_mod_mul(enc[1], h, two, N, ctx);

    if (coin == 0) {
        poly_mul(tmp, enc, g, a, N, ctx);
        BN_copy(enc[0], tmp[0]);
        BN_copy(enc[1], tmp[1]);
    }

    BN_free(tmp[0]);
    BN_free(tmp[1]);


    BN_free(t);
    BN_free(it);
    BN_free(h);
    BN_free(hsqr);
    BN_free(two);
}

static int decrypt_component(BIGNUM * const *enc, const BIGNUM *N,
                             const BIGNUM *a, const BIGNUM *r,
                             int blind, BN_CTX *ctx)
{
    BIGNUM *tmp;
    BIGNUM *tmp2;
    int ret;

    tmp  = BN_new();
    tmp2 = BN_new();
	
    BN_mod_mul(tmp, r, enc[1], N, ctx);
    BN_mod_add(tmp2, tmp, enc[0], N, ctx);
	
    ret = BN_kronecker(tmp2, N, ctx);
    
    if (gt(a, enc, N, ctx) == -1)
        ret *= blind;

    BN_free(tmp);
	
    return ret;
}


int nua_encrypt(const ibe_master_param *master_param, const ibe_pub_key *pk,
                const uint8_t *message, size_t n_bits, uint8_t *ciphertext,
                size_t ct_buf_size)
{
    uint8_t c;
    int i;
    int j;
    int k;
    int m;
    const BIGNUM *N = (const BIGNUM*)master_param;
    BIGNUM *enc[2];
    size_t nb;
    size_t rem;
    const size_t bytes_per_elem = BN_num_bytes(N);
    struct symbols_lst jacobis;
    BIGNUM *pubs[2];
    BN_CTX * ctx;
    uint8_t *coins[2];
    const struct nua_ibe_pub_key *n_pk = (const struct nua_ibe_pub_key*)pk;
    
    if (ct_buf_size < nua_ciphertext_size(master_param, pk, message, n_bits))
        return -1;

    ctx = BN_CTX_new();
    BN_CTX_start(ctx);

    pubs[0] = n_pk->a;
    pubs[1] = BN_new();
    BN_sub(pubs[1], N, pubs[0]);

    enc[0] = BN_new();
    enc[1] = BN_new();


    init_jacobis(&jacobis);
    precalc_jacobis(&jacobis, N, n_bits);

    for (k = 0; k < 2; k++) {
        coins[k] = (uint8_t*)malloc((n_bits  + 7) / 8);
        RAND_bytes(coins[k], (n_bits  + 7) / 8);
    }

    for(i = 0; i < n_bits; i += 8) {
        c = message[i/8];
        for(j = 0; j < 8; j++) {
            for (k = 0; k < 2; k++) {                
                encrypt_component(enc, N, pubs[k], n_pk->g, (c & 0x80) ? -1 : 1,
                                  coins[k][i / 8] & 1, &jacobis, ctx);

                for (m = 0; m < 2; m++) {
                    nb = BN_num_bytes(enc[m]);
                    rem = bytes_per_elem - nb;
                    while (rem--)
                        *ciphertext++ = 0;
                    BN_bn2bin(enc[m], ciphertext);
                    ciphertext += nb;
                }
            }
            c <<= 1;
            coins[0][i / 8] >>= 1;
            coins[1][i / 8] >>= 1;
        }
    }

    BN_CTX_end(ctx);
    BN_CTX_free(ctx);

    BN_free(pubs[1]);

    BN_free(enc[0]);
    BN_free(enc[1]);

    free(coins[0]);
    free(coins[1]);
    destroy_jacobis(&jacobis);

    return 0;
}


int nua_decrypt(const ibe_master_param *master_param, const ibe_sec_key *sk,
                const uint8_t *ciphertext, size_t ct_size, uint8_t *message,
                size_t msg_buf_size)
{
    const BIGNUM *N = (const BIGNUM*)master_param;
    const struct nua_ibe_sec_key *n_sk = (const struct nua_ibe_sec_key*)sk;
    const int sign = id_sign(n_sk->a, n_sk->r, N);
    const int offset = (sign == 1) ? 0 : 1;
    const size_t bytes_per_elem = BN_num_bytes(N);
    size_t n_bits = ct_size / (bytes_per_elem * 4);
    int i;
    int j;
    BIGNUM *enc[2];
    uint8_t c;
    const size_t n_bytes = n_bits / 8;
    BN_CTX *ctx;
    BIGNUM *a;
    int blind;

    if ((n_bits + 7) / 8 < msg_buf_size)
        return -1;

    ctx = BN_CTX_new();
    BN_CTX_start(ctx);

    enc[0] = BN_new();
    enc[1] = BN_new();

    a = BN_new();
    if (sign == 1)
        BN_copy(a, n_sk->a);
    else
        BN_sub(a, N, n_sk->a);

    blind = decrypt_component(n_sk->g, N, a, n_sk->r, 1, ctx);

    for (i = 0; i < n_bytes; i++) {
        c = 0;
        for (j = 0; j < 8; j++) {
            c <<= 1;
            BN_bin2bn(ciphertext + 2*offset*bytes_per_elem,
                      bytes_per_elem, enc[0]);
            BN_bin2bn(ciphertext + (2*offset + 1)*bytes_per_elem,
                      bytes_per_elem, enc[1]);

            ciphertext += bytes_per_elem * 4;

            c |= (decrypt_component(enc, N, a, n_sk->r, blind, ctx) == -1)
                  ? 1 : 0;
        }
        message[i] = c;
    }

    BN_CTX_end(ctx);
    BN_CTX_free(ctx);

    BN_free(enc[0]);
    BN_free(enc[1]);
    BN_free(a);

    return 0;
}
