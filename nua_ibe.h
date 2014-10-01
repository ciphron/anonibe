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


#ifndef NUA_IBE_H
#define NUA_IBE_H

#include <openssl/bn.h>
#include "ibe.h"

struct ibe_scheme *nua_get_scheme();

int nua_master_keygen(struct ibe_master_keypair *keypair, size_t len);

ibe_sec_key *nua_extract(const ibe_master_key *mk, const ibe_pub_key *pk);

ibe_pub_key *nua_derive_pub_key(const ibe_master_param *master_param,
                                const uint8_t *id, size_t id_len);

size_t nua_ciphertext_size(const ibe_master_param *master_param,
                           const ibe_pub_key *pk, const uint8_t *message,
                           size_t nbits);

int nua_encrypt(const ibe_master_param *master_param, const ibe_pub_key *pk,
                const uint8_t *message, size_t n_bits, uint8_t *ciphertext,
                size_t ct_buf_size);

int nua_decrypt(const ibe_master_param *master_param, const ibe_sec_key *sk,
                const uint8_t *ciphertext, size_t ct_size, uint8_t *message,
                  size_t msg_buf_size);

#endif /* NUA_IBE_H */
