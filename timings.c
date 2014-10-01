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
#include <math.h>
#include <openssl/bio.h>
#include <openssl/err.h>
#include <openssl/crypto.h>
#include <openssl/err.h>
#include <openssl/rand.h>
#include <openssl/bn.h>
#include <openssl/sha.h>
#include <sys/time.h>

#include "ibe.h"
#include "cocks_ibe.h"
#include "ag_ibe.h"
#include "nua_ibe.h"
#include "jb_ibe.h"

#define REPETITIONS 50
#define PRIME_SIZE_BITS 512
#define LIMIT_MULTIPLE_PRIME_SIZE 4
#define MESSAGE_LEN_BITS 128

#define NUM_SCHEMES 4
const char * const SCHEMES[NUM_SCHEMES] = {"cocks", "ag", "nua", "jb"};

struct ibe_scheme *create_scheme(const char *name)
{
    if (!strcmp(name, "cocks")) {
        return cocks_get_scheme();
    }
    else if (!strcmp(name, "ag")) {
        return ag_get_scheme();
    }
    else if (!strcmp(name, "nua")) {
        return nua_get_scheme();
    }
    else if (!strcmp(name, "jb")) {
        return jb_get_scheme();
    }
    else
        return NULL;
}


int run_tests(FILE *f, const char *scheme_name, int prime_size)
{

    struct ibe_scheme *scheme;
    struct ibe_master_keypair keypair;
    ibe_pub_key *pk;
    ibe_sec_key *sk;
    uint8_t *id = "Sample id";
    size_t id_len = strlen(id);
    uint8_t *msg;
    uint8_t *dec_msg;
    uint8_t *ciphertext;
    size_t ct_buf_size;
    int i;
    float *enc_times;
    float *dec_times;
    struct timeval before;
    struct timeval after;
    float t;
    float avg_enc_time;
    float avg_dec_time;
    float dev_enc_time;
    float dev_dec_time;
    const int msg_buf_size = (MESSAGE_LEN_BITS + 7) / 8;


    scheme = create_scheme(scheme_name);
    if (scheme == NULL) {
        fprintf(stderr, "Failed to find scheme\n");
        return -1;
    }

    if (MESSAGE_LEN_BITS % 8 != 0) {
        fprintf(stderr, "Not all schemes currently support messages whose "
                "length are not a multiple of 8 bits\n");
    }
    
    /* Generate random message */
    msg = (uint8_t*)malloc(msg_buf_size);
    dec_msg = (uint8_t*)malloc(msg_buf_size);

    RAND_bytes(msg, msg_buf_size);
    dec_msg[msg_buf_size - 1] = msg[msg_buf_size - 1];

    scheme->master_keygen(&keypair, prime_size);
    pk = scheme->derive_pub_key(keypair.master_param, id, id_len);
    sk = scheme->extract(keypair.master_key, pk);
    ct_buf_size = scheme->ciphertext_size(keypair.master_param, pk,
                                          msg, MESSAGE_LEN_BITS);
    ciphertext = (uint8_t*)malloc(ct_buf_size);
    enc_times = (float*)malloc(REPETITIONS * sizeof(float));
    dec_times = (float*)malloc(REPETITIONS * sizeof(float));
    for (i = 0; i < REPETITIONS; i++) {
        gettimeofday(&before, NULL);
        scheme->encrypt(keypair.master_param, pk, msg, MESSAGE_LEN_BITS,
                        ciphertext, ct_buf_size);
        gettimeofday(&after, NULL);
        t = ((after.tv_sec - before.tv_sec)*1000000 + after.tv_usec - before.tv_usec);
        enc_times[i] = t;

        gettimeofday(&before, NULL);
        scheme->decrypt(keypair.master_param, sk, ciphertext, ct_buf_size,
                        dec_msg, msg_buf_size);
        gettimeofday(&after, NULL);
        t = ((after.tv_sec - before.tv_sec)*1000000 + after.tv_usec - before.tv_usec);
        dec_times[i] = t;

        if (strncmp(dec_msg, msg, msg_buf_size) != 0) {
            fprintf(stderr, "Correctness test failed - on iteration %d\n", i);
            printf("Decrypted string: %s\n", dec_msg);
        }
    }

    avg_enc_time = 0.0f;
    avg_dec_time = 0.0f;
    for (i = 0; i < REPETITIONS; i++) {
        avg_enc_time += enc_times[i];
        avg_dec_time += dec_times[i];
    }
    avg_enc_time /= REPETITIONS;
    avg_dec_time /= REPETITIONS;

    dev_enc_time = 0.0f;
    dev_dec_time = 0.0f;
    for (i = 0; i < REPETITIONS; i++) {
        dev_enc_time += (enc_times[i] - avg_enc_time) *
            (enc_times[i] - avg_enc_time);
        dev_dec_time += (dec_times[i] - avg_dec_time) *
            (dec_times[i] - avg_dec_time);
    }
    dev_enc_time = sqrt(dev_enc_time / REPETITIONS);
    dev_dec_time = sqrt(dev_dec_time / REPETITIONS);

    /* Convert to ms */
    avg_enc_time /= 1000.0f;
    dev_enc_time /= 1000.0f;
    avg_dec_time /= 1000.0f;
    dev_dec_time /= 1000.0f;

    /* printf("Encryption Time:\n"); */
    /* printf("Average: %f ms\n", avg_enc_time / 1000.0f); */
    /* printf("Std Deviation: %f ms\n", dev_enc_time / 1000.0f); */

    /* printf("Decryption Time:\n"); */
    /* printf("Average: %f ms\n", avg_dec_time / 1000.0f); */
    /* printf("Std Deviation: %f ms\n", dev_dec_time / 1000.0f); */

    printf("%d\t%f\t%f\t%f\t%f\n",
           prime_size * 2, /* Modulus size */
           avg_enc_time, dev_enc_time,
           avg_dec_time, dev_dec_time);

    fprintf(f, "%d\t%f\t%f\t%f\t%f\n",
           prime_size * 2, /* Modulus size */
           avg_enc_time, dev_enc_time,
           avg_dec_time, dev_dec_time);


    free(ciphertext);
    free(enc_times);
    free(dec_times);
    free(msg);
    free(dec_msg);

    return 0;
}

int main(int argc, char *argv[])
{
    int size = PRIME_SIZE_BITS;
    int i;
    int j;
    
    for (i = 0; i < 1; i++) {
        char name[128];
        FILE *f;
        sprintf(name, "res_%s.dat", SCHEMES[i]);

        f = fopen(name, "w");

        printf("Scheme %s: \n", SCHEMES[i]);
        for (j = 1; j <= LIMIT_MULTIPLE_PRIME_SIZE; j++) {
            run_tests(f, SCHEMES[i], j*size);
        }

        fclose(f);
    }

    return 0;
}
