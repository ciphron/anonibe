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


#ifndef COCKS_BASE_H
#define COCKS_BASE_H

#include <stdint.h>
#include <openssl/bn.h>

struct cocks_master_key {
	BIGNUM * p;
	BIGNUM * q;
};

struct cocks_ibe_sec_key {
    BIGNUM *a;
    BIGNUM *r;
};

struct symbol_st {
	BIGNUM * s;
	BIGNUM * is;
	struct symbol_st * next;
};

struct symbols_lst {
	struct symbol_st * j[2]; /* 0 -> +1, 1 -> -1*/
};

int fdh(const uint8_t *message, size_t len, uint8_t *dest, size_t dsize);
int masterkeygen(struct cocks_master_key *mk, int length);
int getkey(BIGNUM * a, const uint8_t * id, int len, const BIGNUM * N);
int extract(BIGNUM * r, const BIGNUM *p, const BIGNUM *q, const BIGNUM * a);
int id_sign(const BIGNUM * id, const BIGNUM * r, const BIGNUM * N);
void init_jacobis(struct symbols_lst *jacobis);
void destroy_jacobis(struct symbols_lst *jacobis);
int put_jacobi(struct symbols_lst *jacobis, BIGNUM * val, BIGNUM * ival, int bit);
int get_jacobi(struct symbols_lst *jacobis, BIGNUM ** ret, BIGNUM ** iret,
               int bit, const BIGNUM *N, BN_CTX *ctx);
int precalc_jacobis(struct symbols_lst *jacobis, const BIGNUM * N, int num);
int cocks_encrypt_bit(struct symbols_lst *jacobis, BIGNUM * enc,
                      const BIGNUM *N, const BIGNUM * a, int bit);
int cocks_decrypt_bit(const BIGNUM *s, const BIGNUM *r, const BIGNUM *N);


#endif /* COCKS_BASE_H */
