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


#ifndef IBE_H
#define IBE_H

#include <stdint.h>    

typedef void * ibe_master_param;
typedef void * ibe_master_key;
typedef void * ibe_pub_key;
typedef void * ibe_sec_key;

struct ibe_master_keypair {
    ibe_master_param *master_param;
    ibe_master_key *master_key;
};

struct ibe_scheme {
    int (*master_keygen)(struct ibe_master_keypair *keypair, size_t len);

    ibe_sec_key *(*extract)(const ibe_master_key *mk, const ibe_pub_key *pk);

    ibe_pub_key *(*derive_pub_key)(const ibe_master_param *master_param,
                                   const uint8_t *id,
                                   size_t id_len);

    size_t (*ciphertext_size)(const ibe_master_param *master_param,
                              const ibe_pub_key *pk,
                              const uint8_t *message, size_t nbits);

    int (*encrypt)(const ibe_master_param *master_param, const ibe_pub_key *pk,
                   const uint8_t *message, size_t n_bits, uint8_t *ciphertext,
                   size_t ct_buf_size);

    int (*decrypt)(const ibe_master_param *master_param, const ibe_sec_key *sk,
                   const uint8_t *ciphertext, size_t ct_size, uint8_t *message,
                   size_t msg_buf_size);
};

#endif /* IBE_H */
