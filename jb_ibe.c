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


/* Implementation of the Jhanwar and Barau
 * (http://dx.doi.org/10.1007/978-3-642-01440-6_25) variant of the 
 * Boneh, Gentry and Hamburg IBE (http://eprint.iacr.org/2007/177.pdf)
 * Variable names follow the names used in the paper
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <math.h>
#include <openssl/sha.h>
#include <openssl/bn.h>
#include <assert.h>

#include "cocks_base.h"
#include "cocks_ibe.h"
#include "jb_ibe.h"

#define MAX(x, y) ((x) > (y) ? (x) : (y))
#define MIN(x, y) ((x) < (y) ? (x) : (y))

struct jb_ibe_master_param {
    BIGNUM *N;
    BIGNUM *u;
    size_t prime_size;
};

struct jb_ibe_master_key {
    BIGNUM *N;
    BIGNUM *u;
    BIGNUM *p;
    BIGNUM *q;
};

struct jb_ibe_sec_key {
    BIGNUM *R;
    BIGNUM *r;
    int sign; /* +1 for R and -1 for uR */
};

struct ibe_scheme jb_scheme = {
    jb_master_keygen,
    jb_extract,
    jb_derive_pub_key,
    jb_ciphertext_size,
    jb_encrypt,
    jb_decrypt
};

static void encode_be32(uint8_t *dest, uint32_t v);
static uint32_t decode_be32(const uint8_t *src);

static int security_level(size_t prime_size)
{
    int level;
    /* this is chosen arbitrary but it results in very loose approximations
     * for bits of security */
    const int COMPL_COEFF = 2.27; 
    

    switch (prime_size) {
        case 512: 
            level = 80;
            break;
        case 1024:
            level = 112;
            break;
        case 1536:
            level = 128;
            break;
        default:
            level = round(COMPL_COEFF *
                          pow(prime_size / 2.0, 1.0 / 3.0) *
                          pow(log(prime_size / 2.0), 2.0 / 3.0));
            break;
    }
            
    return level;
}

static void rand_sol(BIGNUM *x, BIGNUM *y, const BIGNUM *R, const BIGNUM *s,
                     const BIGNUM *S, const BIGNUM *N, BN_CTX *ctx)
{
    BIGNUM *t = BN_new();
    BIGNUM *tsqr = BN_new();
    unsigned char found = 0;

    /* Temporaries */
    BIGNUM *a = BN_new();
    BIGNUM *b = BN_new();
    BIGNUM *c = BN_new();

    BIGNUM *two = BN_new();

    while (!found) {
        BN_rand(t, BN_num_bits(N), -1, 0);
        BN_mod_sqr(tsqr, t, N, ctx);
        BN_mod_mul(b, tsqr, S, N, ctx);
        BN_mod_add(a, R, b, N, ctx);
        BN_gcd(b, a, N, ctx);
        found = BN_is_one(b);
    }

    /* Now a = R + St^2 */
    BN_mod_mul(b, s, a, N, ctx); // multiply by s
    BN_mod_inverse(a, b, N, ctx); // get inverse

    /* Now a = s*(R + St^2) */

    /* Compute y */
    BN_mod_mul(b, S, tsqr, N, ctx);
    BN_mod_sub(c, R, b, N, ctx);
    BN_mod_mul(y, c, a, N, ctx); // Compute y as (R - St^2) / (s*(R + St^2))

    /* Compute x */
    BN_bin2bn((unsigned char *)"\x2", 1, two);
    BN_mod_mul(b, S, t, N, ctx);
    BN_mod_mul(c, two, b, N, ctx);
    BN_mod_mul(b, c, a, N, ctx);
    BN_sub(x, N, b);

    BN_free(t);
    BN_free(tsqr);
    BN_free(a);
    BN_free(b);
    BN_free(c);
    BN_free(two);

}


struct ibe_scheme *jb_get_scheme()
{
    return &jb_scheme;
}

int jb_master_keygen(struct ibe_master_keypair *keypair, size_t len)
{
    struct jb_ibe_master_param *j_mp = 
        (struct jb_ibe_master_param*)
        malloc(sizeof(struct jb_ibe_master_param));
    struct jb_ibe_master_key *j_mk = 
        (struct jb_ibe_master_key*)
        malloc(sizeof(struct jb_ibe_master_key));
    struct cocks_master_key *c_mk;
    BN_CTX *ctx = BN_CTX_new();

    BN_CTX_start(ctx);
    
    cocks_master_keygen(keypair, len);
    j_mp->N = (BIGNUM*)keypair->master_param;
    c_mk = (struct cocks_master_key*)keypair->master_key;
    j_mp->u = BN_new();
    j_mp->prime_size = len;
    do {
        BN_rand(j_mp->u, BN_num_bits(j_mp->N), -1, 0);
    }
    while (BN_kronecker(j_mp->u, c_mk->p, ctx) == 1 ||
           BN_kronecker(j_mp->u, c_mk->q, ctx) == 1);

    j_mk->N = BN_new();
    j_mk->u = BN_new();
    BN_copy(j_mk->N, j_mp->N);
    BN_copy(j_mk->u, j_mp->u);
    j_mk->p = c_mk->p;
    j_mk->q = c_mk->q;

    keypair->master_param = (ibe_master_param*)j_mp;
    keypair->master_key = (ibe_master_key*)j_mk;

    BN_CTX_end(ctx);
    BN_CTX_free(ctx); 
}

ibe_sec_key *jb_extract(const ibe_master_key *mk, const ibe_pub_key *pk)
{
    const struct jb_ibe_master_key *j_mk = (const struct jb_ibe_master_key*)mk;
    const BIGNUM *R = (const BIGNUM*)pk;
    struct jb_ibe_sec_key *sk = 
        (struct jb_ibe_sec_key*)malloc(sizeof(struct jb_ibe_sec_key));
    BN_CTX *ctx = BN_CTX_new();

    BN_CTX_start(ctx);

    sk->r = BN_new();
    if (BN_kronecker(R, j_mk->p, ctx) == 1 && 
            BN_kronecker(R, j_mk->q, ctx) == 1) {
        extract(sk->r, j_mk->p, j_mk->q, R);
        sk->sign = 1;
    }
    else {
        BIGNUM *uR = BN_new();

        BN_mod_mul(uR, R, j_mk->u, j_mk->N, ctx);
        extract(sk->r, j_mk->p, j_mk->q, uR);
        sk->sign = -1;

        BN_free(uR);
    }

    sk->R = BN_new();
    BN_copy(sk->R, R);
    
    BN_CTX_end(ctx);
    BN_CTX_free(ctx); 

    return (ibe_sec_key*)sk;
}


ibe_pub_key *jb_derive_pub_key(const ibe_master_param *master_param,
                               const uint8_t *id,  size_t id_len)
{
    const struct jb_ibe_master_param *j_mp = 
        (const struct jb_ibe_master_param*)master_param;
    
    return cocks_derive_pub_key((ibe_master_param*)j_mp->N, id, id_len);
}



size_t jb_ciphertext_size(const ibe_master_param *master_param, const ibe_pub_key *pk,
                           const uint8_t *message, size_t n_bits)
{
    const struct jb_ibe_master_param *j_mp = 
        (const struct jb_ibe_master_param*)master_param;
    
    // includes 32-bit unsigned integer in Big Endian that encodes size of 
    // plaintext (in bits)

    int kappa = MIN(MAX(ceil(sqrt(n_bits)),
                        security_level(j_mp->prime_size)), n_bits);

    return (BN_num_bytes(j_mp->N) * kappa * 2) +
             (((n_bits * 2) + 7) / 8) + 4;
}


static int encrypt_component(int *c, int j, int kappa,
                             const BIGNUM *R,  BIGNUM * const *us,
                             BIGNUM * const *xs, BIGNUM * const *ys, 
                             int bit, const BIGNUM *N, BN_CTX *ctx)
{
    BIGNUM *one;
    BIGNUM *two;
    BIGNUM *hsqr;
    BIGNUM *tmp1;
    BIGNUM *tmp2;
    BIGNUM *tmp3;
    BIGNUM *tmp4;
    int j1;
    int j2;

   
    if((bit != 1 && bit != -1) || kappa <= 0)
        return -1;

    one = BN_new();
    BN_bin2bn((unsigned char *)"\x1", 1, one);
    two = BN_new();
    BN_bin2bn((unsigned char *)"\x2", 1, two);

    tmp1 = BN_new();
    tmp2 = BN_new();
    tmp3 = BN_new();
    tmp4 = BN_new();


    if (j < kappa) {
        /* 2 * u_j */
        BN_mod_mul(tmp1, two, us[j], N, ctx);

        /* 2 * u_j * y_j */
        BN_mod_mul(tmp2, tmp1, ys[j], N, ctx);

        /* g_j(u_j) = 2 * u_j * y_j  + 2 */
        BN_mod_add(tmp3, tmp2, two, N, ctx);

        /* bit * (g_j(u_j) | N) */
        *c = bit * BN_kronecker(tmp3, N, ctx);
    }
    else {
        j1 = j / kappa;
        j2 = j % kappa;

        /* u_j1 * u_j2 */
        BN_mod_mul(tmp2, us[j1], us[j2], N, ctx);

        /* 2 * u_j1 * u_j2 */
        BN_mod_mul(tmp1, tmp2, two, N, ctx);

        /* y_j1 * y_j2 */
        BN_mod_mul(tmp2, ys[j1], ys[j2], N, ctx);

        /* x_j1 * x_j2 */
        BN_mod_mul(tmp3, xs[j1], xs[j2], N, ctx);

        /* Calculate quotient of R*x_j1*x_j2 + 1 */
        BN_mod_mul(tmp4, R, tmp3, N, ctx);
        BN_mod_add(tmp3, tmp4, one, N, ctx);
        BN_mod_inverse(tmp4, tmp3, N, ctx);

        /* Calculate y_j1j2 */
        BN_mod_mul(tmp3, tmp2, tmp4, N, ctx);

        BN_mod_mul(tmp2, tmp3, tmp1, N, ctx);
        BN_mod_add(tmp3, tmp2, two, N, ctx);
        *c = bit * BN_kronecker(tmp3, N, ctx);
    }
    
        

    BN_free(tmp1);
    BN_free(tmp2);
    BN_free(tmp3);
    BN_free(tmp4);

    BN_free(one);
    BN_free(two);
}

static int decrypt_component(int c, int j, int kappa,
                             const BIGNUM *R, BIGNUM * const *xs,
                             const BIGNUM *r, const BIGNUM *N, BN_CTX *ctx)

{
    BIGNUM *one;
    BIGNUM *tmp1;
    BIGNUM *tmp2;
    BIGNUM *tmp3;
    int j1;
    int j2;
    int bit;

   
    one = BN_new();
    BN_bin2bn((unsigned char *)"\x1", 1, one);

    tmp1 = BN_new();
    tmp2 = BN_new();
    tmp3 = BN_new();


    if (j < kappa) {
        BN_mod_mul(tmp1, xs[j], r, N, ctx);
        BN_mod_add(tmp2, tmp1, one, N, ctx);
        bit = c * BN_kronecker(tmp2, N, ctx);
    }
    else {
        j1 = j / kappa;
        j2 = j % kappa;
        
        /* 1 / (Rx_j1*x_j2 + 1) */
        BN_mod_mul(tmp1, xs[j1], xs[j2], N, ctx);
        BN_mod_mul(tmp2, R, tmp1, N, ctx);
        BN_mod_add(tmp1, tmp2, one, N, ctx);
        BN_mod_inverse(tmp2, tmp1, N, ctx);

        /* x_j1 + x_j2 */
        BN_mod_add(tmp1, xs[j1], xs[j2], N, ctx);

        /* x_j1j2 = (x_j1 + x_j2) / (Rx_j1*x_j2 + 1) */
        BN_mod_mul(tmp3, tmp1, tmp2, N, ctx);
        
        /* x_j1j2 * r + 1 */
        BN_mod_mul(tmp1, tmp3, r, N, ctx);
        BN_mod_add(tmp2, tmp1, one, N, ctx);

        bit = c * BN_kronecker(tmp2, N, ctx);
    }

    
        

    BN_free(tmp1);
    BN_free(tmp2);
    BN_free(tmp3);

    BN_free(one);

    return bit;
}


int jb_encrypt(const ibe_master_param *master_param, const ibe_pub_key *pk,
                const uint8_t *message, size_t n_bits, uint8_t *ciphertext,
                size_t ct_buf_size)
{
    uint8_t c;
    int c_bit;
    int i;
    int j;
    int k;
    const struct jb_ibe_master_param *j_mp = 
        (const struct jb_ibe_master_param*)master_param;
    const BIGNUM *N = j_mp->N;
    const BIGNUM *u = j_mp->u;
    size_t nb;
    size_t rem;
    const size_t bytes_per_elem = BN_num_bytes(N);
    BN_CTX * ctx;
    const int kappa = MIN(MAX(ceil(sqrt(n_bits)),
                              security_level(j_mp->prime_size)), n_bits);
    const BIGNUM *Rs[2];
    BIGNUM **xs[2];
    BIGNUM **ys[2];
    const BIGNUM *R = (const BIGNUM*)pk;
    BIGNUM *uR;
    BIGNUM **us;
    BIGNUM **Us;
    int bit;
    uint8_t cs[2];
    BIGNUM *t1 = BN_new();
    
    if (ct_buf_size < jb_ciphertext_size(master_param, pk, message, n_bits))
        return -1;

    ctx = BN_CTX_new();
    BN_CTX_start(ctx);

    us = (BIGNUM**)malloc(kappa * sizeof(BIGNUM*));
    Us = (BIGNUM**)malloc(kappa * sizeof(BIGNUM*));

    uR = BN_new();
    BN_mod_mul(uR, j_mp->u, R, N, ctx);

    Rs[0] = R;
    Rs[1] = uR;

    for (i = 0; i < 2; i++) {
        xs[i] = (BIGNUM**)malloc(kappa * sizeof(BIGNUM*));
        ys[i] = (BIGNUM**)malloc(kappa * sizeof(BIGNUM*));
    }

    encode_be32(ciphertext, n_bits);
    ciphertext += 4;
    
    for (i = 0; i < kappa; i++) {
        us[i] = BN_new();
        Us[i] = BN_new();

        BN_rand(us[i], BN_num_bits(N), -1, 0);
        BN_mod_sqr(Us[i], us[i], N, ctx);

        for (j = 0; j < 2; j++) {
            xs[j][i] = BN_new();
            ys[j][i] = BN_new();
            rand_sol(xs[j][i], ys[j][i], Rs[j], us[i], Us[i], N, ctx);

            nb = BN_num_bytes(xs[j][i]);
            rem = bytes_per_elem - nb;
            while (rem--)
                *ciphertext++ = 0;
            BN_bn2bin(xs[j][i], ciphertext);
            ciphertext += nb;
        }
    }

    for(i = 0; i < n_bits; i += 8) {
        c = message[i/8];
        cs[0] = 0;
        cs[1] = 0;
        for(j = 0; j < 8; j++) {
            for (k = 0; k < 2; k++) {
                cs[k] <<= 1;
                encrypt_component(&c_bit, i + j, kappa, Rs[k], us, xs[k],
                                  ys[k], (c & 0x80) ? -1 : 1, N, ctx);

                cs[k] |= (c_bit == -1) ? 1 : 0;
            }

            c <<= 1;
        }
        *ciphertext++ = cs[0];
        *ciphertext++ = cs[1];
    }
    
    for (i = 0; i < kappa; i++) {
        BN_free(us[i]);
        BN_free(Us[i]);
        for (j = 0; j < 2; j++) {
            BN_free(xs[j][i]);
            BN_free(ys[j][i]);
        }
    }

    free(us);
    free(Us);

    free(xs[0]);
    free(xs[1]);
    free(ys[0]);
    free(ys[1]);

    BN_free(uR);

    BN_CTX_end(ctx);
    BN_CTX_free(ctx);


    return 0;
}


int jb_decrypt(const ibe_master_param *master_param, const ibe_sec_key *sk,
                const uint8_t *ciphertext, size_t ct_size, uint8_t *message,
                size_t msg_buf_size)
{

    uint8_t c;
    uint8_t cs;
    int c_bit;
    int i;
    int j;
    size_t n_bits;
    size_t n_bytes;
    const struct jb_ibe_master_param *j_mp = 
        (const struct jb_ibe_master_param*)master_param;
    const struct jb_ibe_sec_key *j_sk = (const struct jb_ibe_sec_key*)sk;
    const int offset = (j_sk->sign == 1) ? 0 : 1;
    const BIGNUM *N = j_mp->N;
    const BIGNUM *u = j_mp->u;
    const size_t bytes_per_elem = BN_num_bytes(N);
    int kappa;
    const BIGNUM *Rs[2];
    BIGNUM **xs;
    const BIGNUM *R = j_sk->R;
    BIGNUM *uR;
    BN_CTX * ctx;
    BIGNUM *atmp = BN_new();


    if (msg_buf_size < 4)
        return -1;

    /* Expect first 4 bytes to represent number of bits (Big Endian uint32) */
    n_bits = decode_be32(ciphertext);

    if ((n_bits + 7) / 8 < msg_buf_size)
        return -1;

    n_bytes = n_bits / 8;
    ciphertext += 4; // skip over the "size field"

    ctx = BN_CTX_new();
    BN_CTX_start(ctx);

    uR = BN_new();
    BN_mod_mul(uR, j_mp->u, R, N, ctx);

    Rs[0] = R;
    Rs[1] = uR;

    kappa = MIN(MAX(ceil(sqrt(n_bits)),
                    security_level(j_mp->prime_size)), n_bits);

    xs = (BIGNUM**)malloc(kappa * sizeof(BIGNUM*));

    for (i = 0; i < kappa; i++) {
        xs[i] = BN_new();
        BN_bin2bn(ciphertext + offset*bytes_per_elem, bytes_per_elem, xs[i]);
        ciphertext += 2 * bytes_per_elem;
    }

    for (i = 0; i < n_bytes; i++) {
        c = 0;
        cs = ciphertext[i*2 + offset];
        for (j = 0; j < 8; j++) {
            c <<= 1;
            c_bit = (cs & 0x80) ? -1 : 1;
            c |= (decrypt_component(c_bit, i*8 + j, kappa, Rs[offset], xs,
                                    j_sk->r, N, ctx) == -1) ? 1 : 0;

            cs <<= 1;
        }
        message[i] = c;
    }

    for (i = 0; i < kappa; i++) {
        BN_free(xs[i]);
    }

    free(xs);

    BN_free(uR);


    BN_CTX_end(ctx);
    BN_CTX_free(ctx);


    return 0;
}


static void encode_be32(uint8_t *dest, uint32_t v)
{
    *dest++ = v >> 24;
    *dest++ = (v >> 16) & 0xFF;
    *dest++ = (v >> 8) & 0xFF;
    *dest = v & 0xFF;
}

static uint32_t decode_be32(const uint8_t *src)
{
    uint32_t v = 0;

    v |= *src++ << 24;
    v |= *src++ << 16;
    v |= *src++ << 8;
    v |= *src;

    return v;
}
