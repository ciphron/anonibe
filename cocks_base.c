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


/* cocks_base.c */
/* Written by Paolo Gasti, 2008 (pgasti@nyit.edu)
/* Extended by Michael Clear, 2013 (clearm@scss.tcd.ie)
 *
 */


#include <stdio.h>
#include <stdlib.h>
#include <openssl/ripemd.h>
#include <openssl/rand.h>
#include <assert.h>
#include <string.h>
#include <openssl/err.h>

#include "cocks_base.h"

int masterkeygen(struct cocks_master_key *mk, int length)
{
	BIGNUM * bn3, * bn4;
	const unsigned int safe = 1;

	bn3 = BN_new();
	bn4 = BN_new();

	uint8_t c3[] = {(uint8_t)0x03};
	uint8_t c4[] = {(uint8_t)0x04};

	BN_bin2bn(c3, 1, bn3);
	BN_bin2bn(c4, 1, bn4);
	mk->p = BN_generate_prime(NULL, length, safe, bn4, bn3, NULL, NULL);
	mk->q = BN_generate_prime(NULL, length, safe, bn4, bn3, NULL, NULL);

	return 0;
}

int fdh(const uint8_t *message, size_t len, uint8_t *hash, size_t dsize)
{
    size_t count = dsize;
    uint8_t buf[RIPEMD160_DIGEST_LENGTH];
    size_t residue = dsize % RIPEMD160_DIGEST_LENGTH;

    RIPEMD160(message, len, buf);	
    memcpy(hash, buf, residue);
    count -= residue;
    hash += residue;
    while(count >= RIPEMD160_DIGEST_LENGTH) {
        RIPEMD160(buf, RIPEMD160_DIGEST_LENGTH, hash);
        memcpy(buf, hash, RIPEMD160_DIGEST_LENGTH);
        hash += RIPEMD160_DIGEST_LENGTH;
        count -= RIPEMD160_DIGEST_LENGTH;
    }

    return 0;
}

/*
 * getkey(key, id, len, N) calculates a value v s.t. the
 * Jacobi Symbol (v/N) == 1. To do that, it calculates k = H(id)
 * and checks if (k/N) == 1. If not, it applies the hash function
 * as long as the Jacobi Symbol is 1
 */
int getkey(BIGNUM * a, const uint8_t * id, int len, const BIGNUM * N)
{
        uint8_t *tmp;
	BN_CTX *ctx = BN_CTX_new();
        const size_t num_bytes = BN_num_bytes(N) - 1;
        uint8_t *buf = (uint8_t*)malloc(num_bytes);
        uint8_t hash[RIPEMD160_DIGEST_LENGTH];

        fdh(id, len, buf, num_bytes);
        BN_bin2bn(hash, num_bytes, a);
        while (BN_kronecker(a, N, ctx) != 1) {
            memcpy(hash, buf, RIPEMD160_DIGEST_LENGTH);
            fdh(hash, RIPEMD160_DIGEST_LENGTH, buf, num_bytes);
            BN_bin2bn(buf, num_bytes, a);
        }

        free(buf);

	BN_CTX_free(ctx);

	return 0;
}



/* Variable names follow "An Identity Based Encryption Scheme based on Quadratic Residues", Clifford Cocks */

int extract(BIGNUM * r, const BIGNUM *p, const BIGNUM *q, const BIGNUM * a)
{
	BN_CTX *ctx = BN_CTX_new();
	BIGNUM * t1, * t2, * m, * bn8, * bn5;
	
	t1 = BN_new();
	t2 = BN_new();
	m  = BN_new();
	bn5 = BN_new();
	bn8 = BN_new();

	/* Calculate module M */
	BN_mul(m, p, q, ctx);
		
	/* Set constant 8^-1 mod M*/
	BN_bin2bn((uint8_t *)"\x8", 1, t1);
	BN_mod_inverse(bn8, t1, m, ctx);
	
	#ifdef DEBUG
	printf("\n8^-1= ");
	BN_print_fp_dec(stdout, bn8);	
	#endif
	
	/* Set constant 5 */
	BN_bin2bn((uint8_t *)"\x5", 1, bn5);
	
	/* Calculate t1 = M + 5 - P - Q mod M */
	BN_mod_add(t1, m, bn5, m, ctx);

	#ifdef DEBUG
	
	printf("\np   = ");
	BN_print_fp_dec(stdout, p);
	printf("\nq   = ");
	BN_print_fp_dec(stdout, q);
	
	#endif

	BN_mod_sub(t2, t1, p, m, ctx);

	BN_mod_sub(t1, t2, q, m, ctx);
	
	/* Calculate t2 = t1 * 1/8 mod M */
	BN_mod_mul(t2, t1, bn8, m, ctx);
	#ifdef DEBUG

	printf("\nstuff=");
	BN_print_fp_dec(stdout, t2);
	
	#endif

	/* Calculate a^t2 */
	
	BN_mod_exp(r, a, t2, m, ctx);
	
	/* free */
	BN_free(t1);
	BN_free(t2);
	BN_free(m);
	BN_free(bn5);
	BN_free(bn8);
	BN_CTX_free(ctx);
	return 0;
}

// returns 1 if r^2=a and -1 if r^2=a
int id_sign(const BIGNUM * id, const BIGNUM * r, const BIGNUM * N)
{
	BN_CTX * ctx = BN_CTX_new();
	BIGNUM * t;
        int ret;
	
	t = BN_new();
	BN_mod_sqr(t, r, N, ctx);
	
	if(BN_cmp(t, id))
            ret = -1;
	else
            ret = 1;
		
	BN_free(t);
	BN_CTX_free(ctx);

        return ret;
}

void init_jacobis(struct symbols_lst *jacobis)
{
	jacobis->j[0] = NULL;
	jacobis->j[1] = NULL;
}

void destroy_jacobis(struct symbols_lst *jacobis)
{
    int i;
    struct symbol_st *s;
    struct symbol_st *tmp;

    for (i = 0; i < 2; i++) {
        s = jacobis->j[i];

        while (s != NULL) {
            BN_free(s->s);
            BN_free(s->is);
            tmp = s;
            s = s->next;
            free(tmp);
        }
    }
}

int put_jacobi(struct symbols_lst *jacobis, BIGNUM * val, BIGNUM * ival,
               int bit)
{
	struct symbol_st * tmp;
	int t;

	if(bit != 1 && bit != -1)
		return 1;

	if(bit == 1)
		t = 0;
	else
		t = 1;
	
	tmp = jacobis->j[t];
	jacobis->j[t] = (struct symbol_st *) malloc (sizeof(struct symbol_st));
	jacobis->j[t]->s = val;
	jacobis->j[t]->is = ival;
	jacobis->j[t]->next = tmp;
	return 0;
}

//bit must be encoded as +1 or -1 
int get_jacobi(struct symbols_lst *jacobis, BIGNUM ** ret, BIGNUM ** iret,
               int bit, const BIGNUM *N, BN_CTX *ctx)
{
	struct symbol_st * tmp;
	int s;
        const int bytes_per_elem = BN_num_bits(N);

	if(bit != 1 && bit != -1)
		return 1;

	if(bit == 1)
            s = 0;
	else
            s = 1;

	tmp = jacobis->j[s];
	if(!tmp) {
            BIGNUM *t   = BN_new();
            BIGNUM *it  = BN_new();
            int b;

            BN_rand(t, bytes_per_elem, -1, 0);
            BN_mod_inverse(it, t, N, ctx);		
            b = BN_kronecker(t, N, ctx);

            while(b != bit) {
                put_jacobi(jacobis, t, it, b);

                t = BN_new();
                it = BN_new();
                BN_rand(t, bytes_per_elem , -1, 0);
                BN_mod_inverse(it, t, N, ctx);                
                b = BN_kronecker(t, N, ctx);
            }

            *ret = t;
            *iret = it;
        }
        else {
            *ret  = tmp->s;
            *iret = tmp->is;

            jacobis->j[s] = jacobis->j[s]->next;
        }
	free (tmp);

	return 0;
}

int precalc_jacobis(struct symbols_lst *jacobis, const BIGNUM * N, int num)
{
	int kp, km;
	BN_CTX *ctx = BN_CTX_new();
	BIGNUM * t, * it;
		
	kp = km = num;
	
	while(km > 0 || kp > 0)
	{
		t   = BN_new();
		it  = BN_new();

		BN_rand(t, BN_num_bits(N), -1, 0);
		BN_mod_inverse(it, t, N, ctx);
		
		if(1 == BN_kronecker(t, N, ctx))
		{
			kp--;
			put_jacobi(jacobis, t, it, 1);
		}
		else
		{
			km--;
			put_jacobi(jacobis, t, it, -1);
		}
		
	}
	
	BN_CTX_free(ctx);
	return 0;
}

int cocks_encrypt_bit(struct symbols_lst *jacobis, BIGNUM * enc,
                      const BIGNUM *N, const BIGNUM *a, int bit) 
{
	BN_CTX *ctx = BN_CTX_new();
	BIGNUM * t, * it, * tmp;
	
	if(bit != 1 && bit != -1)
		return 1;
		
	/*if(get_jacobi(jacobis, &t, &it, bit) == 2)
	{
            precalc_jacobis(jacobis, N, 1);
            get_jacobi(jacobis, &t, &it, bit);
            }*/
        get_jacobi(jacobis, &t, &it, bit, N, ctx);

	tmp = BN_new();	
	BN_mod_mul(tmp, a, it, N, ctx);
	BN_mod_add(enc, tmp, t, N, ctx);

	BN_free(tmp);
	BN_free(t);
	BN_free(it);

	
	BN_CTX_free(ctx);
	return 0;
}

// returns the decrypted bit 1 or -1, or 0 on error
int cocks_decrypt_bit(const BIGNUM *s, const BIGNUM *r, const BIGNUM *N)
{
	BN_CTX *ctx = BN_CTX_new();
	BIGNUM * two, * tmp, * tmp2;
	int ret;
	
	two  = BN_new();
	tmp  = BN_new();
	tmp2 = BN_new();
	
	BN_bin2bn((unsigned char *)"\x2", 1, two);
	BN_mod_mul(tmp, r, two, N, ctx);
	BN_mod_add(tmp2, tmp, s, N, ctx);
	
	ret = BN_kronecker(tmp2, N, ctx);

	BN_free(tmp);
        BN_free(two);
	BN_CTX_free(ctx);
	
	return ret;
}
