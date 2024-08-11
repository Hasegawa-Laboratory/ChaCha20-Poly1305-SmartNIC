#include <net/eth.h>
#include <nfp.h>
#include <nfp/me.h>
#include <nfp/mem_atomic.h>
#include <nfp/mem_bulk.h>
#include <pkt/pkt.h>
#include <stdint.h>

#ifndef NBI
#define NBI 0
#endif

#ifndef PKT_NBI_OFFSET
#define PKT_NBI_OFFSET 128
#endif

#define CHACHA20_QUARTER_ROUND(a, b, c, d) \
    a += b;                                \
    d = rotl32(d ^ a, 16);                 \
    c += d;                                \
    b = rotl32(b ^ c, 12);                 \
    a += b;                                \
    d = rotl32(d ^ a, 8);                  \
    c += d;                                \
    b = rotl32(b ^ c, 7);

__mem40 uint8_t *receive_packet(__xread struct nbi_meta_catamaran *nbi_meta);
void send_packet(__xread struct nbi_meta_catamaran *nbi_meta);
void chacha20_poly1305_aead_encrypt(uint32_t *key, uint32_t *nonce, __mem40 uint32_t *plaintext, __mem40 uint32_t *ciphertext, int msg_len, uint32_t *aad, int aad_len, __mem40 uint32_t *tag);

// key = 0x00010203_04050607_08090a0b_0c0d0e0f_10111213_14151617_18191a1b_1c1d1e1f
__shared __cls32 uint8_t key[32] = {
    0x03, 0x02, 0x01, 0x00, 0x07, 0x06, 0x05, 0x04,
    0x0b, 0x0a, 0x09, 0x08, 0x0f, 0x0e, 0x0d, 0x0c,
    0x13, 0x12, 0x11, 0x10, 0x17, 0x16, 0x15, 0x14,
    0x1b, 0x1a, 0x19, 0x18, 0x1f, 0x1e, 0x1d, 0x1c,
};

// nonce = 0x00000000_0000004a_00000000
__shared __cls32 uint8_t nonce[12] = {
    0x00, 0x00, 0x00, 0x00, 0x4a, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
};

__shared __ctm32 uint8_t aad[32];

int main(void) {
    __xread struct nbi_meta_catamaran nbi_meta;
    __mem40 uint8_t *pkt;
    int offset = MAC_PREPEND_BYTES * 2 + NET_ETH_ALEN;

    for (;;) {
        pkt = receive_packet(&nbi_meta);
        chacha20_poly1305_aead_encrypt((uint32_t *)key, (uint32_t *)nonce, (__mem40 uint32_t *)(pkt+offset), (__mem40 uint32_t *)(pkt + offset), nbi_meta.pkt_info.len - offset, (uint32_t *)aad, 32, (__mem40 uint32_t *)(pkt + offset));
        send_packet(&nbi_meta);
    }

    return 0;
}

uint32_t byte_swap(uint32_t x) {
    return (x & 0x000000ff) << 24 | (x & 0x0000ff00) <<  8 |
           (x & 0x00ff0000) >>  8 | (x & 0xff000000) >> 24;
}

__mem40 uint8_t *receive_packet(__xread struct nbi_meta_catamaran *nbi_meta) {
    int island, pnum, pkt_off;
    __mem40 uint8_t *pkt_hdr;

    pkt_nbi_recv(nbi_meta, sizeof(struct nbi_meta_catamaran));

    pkt_off = PKT_NBI_OFFSET;
    island = nbi_meta->pkt_info.isl;
    pnum = nbi_meta->pkt_info.pnum;

    pkt_hdr = pkt_ctm_ptr40(island, pnum, pkt_off);

    return pkt_hdr;
}

void send_packet(__xread struct nbi_meta_catamaran *nbi_meta) {
    int island, pnum, plen, pkt_off;
    __gpr struct pkt_ms_info msi;
    __mem40 uint8_t *pbuf;
    uint16_t q_dst = 0;

    /* Write the MAC egress CMD and adjust offset and len accordingly */
    pkt_off = PKT_NBI_OFFSET + 2 * MAC_PREPEND_BYTES;
    island = nbi_meta->pkt_info.isl;
    pnum = nbi_meta->pkt_info.pnum;
    pbuf = pkt_ctm_ptr40(island, pnum, 0);
    plen = nbi_meta->pkt_info.len - MAC_PREPEND_BYTES;

    /* Set egress tm queue */
    q_dst = PORT_TO_CHANNEL(nbi_meta->port);

    msi = pkt_msd_write(pbuf, pkt_off - MAC_PREPEND_BYTES);
    pkt_nbi_send(island, pnum, &msi, plen, NBI, q_dst, nbi_meta->seqr,
                 nbi_meta->seq, PKT_CTM_SIZE_256);
}

void chacha20_poly1305_aead_encrypt(uint32_t *key, uint32_t *nonce, __mem40 uint32_t *plaintext, __mem40 uint32_t *ciphertext, int msg_len, uint32_t *aad, int aad_len, __mem40 uint32_t *tag) {
    /* chacha variable */
    __lmem uint32_t s0, s1, s2, s3, s4, s5, s6, s7, s8, s9, s10, s11, s12, s13, s14, s15;
    __gpr uint32_t a0, a1, a2, a3, a4, a5, a6, a7, a8, a9, a10, a11, a12, a13, a14, a15;
    /* poly variable */
    __gpr uint32_t acc0 = 0, acc1 = 0, acc2 = 0, acc3 = 0, acc4 = 0;
    __lmem uint32_t r0, r1, r2, r3, ps0, ps1, ps2, ps3;
    __lmem uint64_t block[5];
    __gpr uint64_t buf0, buf1, buf2, buf3, buf4;
    __lmem uint64_t carry;
    /* chacha-poly variable */
    __gpr int bytes = msg_len;
    __mem40 uint32_t *cipher = ciphertext;
    __lmem uint32_t aad_length = aad_len, msg_length = msg_len;
    int i;

    /* init chacha state (counter = 0) */
    s0 = 0x61707865;
    s1 = 0x3320646e;
    s2 = 0x79622d32;
    s3 = 0x6b206574;
    s4 = key[0];
    s5 = key[1];
    s6 = key[2];
    s7 = key[3];
    s8 = key[4];
    s9 = key[5];
    s10 = key[6];
    s11 = key[7];
    s12 = 0;
    s13 = nonce[0];
    s14 = nonce[1];
    s15 = nonce[2];

    /* generate poly1305 key */
    a0 = s0;
    a1 = s1;
    a2 = s2;
    a3 = s3;
    a4 = s4;
    a5 = s5;
    a6 = s6;
    a7 = s7;
    a8 = s8;
    a9 = s9;
    a10 = s10;
    a11 = s11;
    a12 = s12;
    a13 = s13;
    a14 = s14;
    a15 = s15;

    for (i = 0; i < 10; i++) {
        CHACHA20_QUARTER_ROUND(a0, a4, a8, a12)
        CHACHA20_QUARTER_ROUND(a1, a5, a9, a13)
        CHACHA20_QUARTER_ROUND(a2, a6, a10, a14)
        CHACHA20_QUARTER_ROUND(a3, a7, a11, a15)

        CHACHA20_QUARTER_ROUND(a0, a5, a10, a15)
        CHACHA20_QUARTER_ROUND(a1, a6, a11, a12)
        CHACHA20_QUARTER_ROUND(a2, a7, a8, a13)
        CHACHA20_QUARTER_ROUND(a3, a4, a9, a14)
    }

    a0 += s0;
    a1 += s1;
    a2 += s2;
    a3 += s3;
    a4 += s4;
    a5 += s5;
    a6 += s6;
    a7 += s7;
    a8 += s8;
    a9 += s9;
    a10 += s10;
    a11 += s11;
    a12 += s12;
    a13 += s13;
    a14 += s14;
    a15 += s15;

    r0 = a0 & 0x0fffffff;
    r1 = a1 & 0x0ffffffc;
    r2 = a2 & 0x0ffffffc;
    r3 = a3 & 0x0ffffffc;
    ps0 = a4;
    ps1 = a5;
    ps2 = a6;
    ps3 = a7;

    s12++;

    for (;;) {
        if (bytes == 0) break;
        a0 = s0;
        a1 = s1;
        a2 = s2;
        a3 = s3;
        a4 = s4;
        a5 = s5;
        a6 = s6;
        a7 = s7;
        a8 = s8;
        a9 = s9;
        a10 = s10;
        a11 = s11;
        a12 = s12;
        a13 = s13;
        a14 = s14;
        a15 = s15;

        for (i = 0; i < 10; i++) {
            CHACHA20_QUARTER_ROUND(a0, a4, a8, a12)
            CHACHA20_QUARTER_ROUND(a1, a5, a9, a13)
            CHACHA20_QUARTER_ROUND(a2, a6, a10, a14)
            CHACHA20_QUARTER_ROUND(a3, a7, a11, a15)

            CHACHA20_QUARTER_ROUND(a0, a5, a10, a15)
            CHACHA20_QUARTER_ROUND(a1, a6, a11, a12)
            CHACHA20_QUARTER_ROUND(a2, a7, a8, a13)
            CHACHA20_QUARTER_ROUND(a3, a4, a9, a14)
        }

        a0 += s0;
        a1 += s1;
        a2 += s2;
        a3 += s3;
        a4 += s4;
        a5 += s5;
        a6 += s6;
        a7 += s7;
        a8 += s8;
        a9 += s9;
        a10 += s10;
        a11 += s11;
        a12 += s12;
        a13 += s13;
        a14 += s14;
        a15 += s15;

        if (s12 == 0) {
            r0 = a0 & 0x0fffffff;
            r1 = a1 & 0x0ffffffc;
            r2 = a2 & 0x0ffffffc;
            r3 = a3 & 0x0ffffffc;
            ps0 = a4;
            ps1 = a5;
            ps2 = a6;
            ps3 = a7;

            s12++;
            continue;
        }

        if (bytes < 61) {
            switch((bytes - 1) >> 2) {
                case 14: ciphertext[14] = a14 ^ plaintext[14];
                case 13: ciphertext[13] = a13 ^ plaintext[13];
                case 12: ciphertext[12] = a12 ^ plaintext[12];
                case 11: ciphertext[11] = a11 ^ plaintext[11];
                case 10: ciphertext[10] = a10 ^ plaintext[10];
                case  9: ciphertext[9]  =  a9 ^ plaintext[9];
                case  8: ciphertext[8]  =  a8 ^ plaintext[8];
                case  7: ciphertext[7]  =  a7 ^ plaintext[7];
                case  6: ciphertext[6]  =  a6 ^ plaintext[6];
                case  5: ciphertext[5]  =  a5 ^ plaintext[5];
                case  4: ciphertext[4]  =  a4 ^ plaintext[4];
                case  3: ciphertext[3]  =  a3 ^ plaintext[3];
                case  2: ciphertext[2]  =  a2 ^ plaintext[2];
                case  1: ciphertext[1]  =  a1 ^ plaintext[1];
                case  0: ciphertext[0]  =  a0 ^ plaintext[0];
            }
            break;
        }

        ciphertext[0]  =  a0 ^ plaintext[0];
        ciphertext[1]  =  a1 ^ plaintext[1];
        ciphertext[2]  =  a2 ^ plaintext[2];
        ciphertext[3]  =  a3 ^ plaintext[3];
        ciphertext[4]  =  a4 ^ plaintext[4];
        ciphertext[5]  =  a5 ^ plaintext[5];
        ciphertext[6]  =  a6 ^ plaintext[6];
        ciphertext[7]  =  a7 ^ plaintext[7];
        ciphertext[8]  =  a8 ^ plaintext[8];
        ciphertext[9]  =  a9 ^ plaintext[9];
        ciphertext[10] = a10 ^ plaintext[10];
        ciphertext[11] = a11 ^ plaintext[11];
        ciphertext[12] = a12 ^ plaintext[12];
        ciphertext[13] = a13 ^ plaintext[13];
        ciphertext[14] = a14 ^ plaintext[14];
        ciphertext[15] = a15 ^ plaintext[15];

        s12++;

        bytes -= 64;
        plaintext  += 16;
        ciphertext += 16;
    }

    /* auth date is 16 byte aligned */
    bytes = (((aad_len >> 4) + 1) << 4) + (((msg_len >> 4) + 1) << 4) + 16;
    /* gen mac */
    for (;;) {
        /* make block */
        if (bytes <= 0) break;
        block[0] = 0;
        block[1] = 0;
        block[2] = 0;
        block[3] = 0;
        if (bytes > (((msg_len >> 4) + 1) << 4) + 16) {
            if (bytes - (((msg_len >> 4) + 1) << 4) - 16 <= 16) {
                int remain = 0;
                switch (aad_len >> 2) {
                case 3: block[2] = aad[2]; remain++; aad_len -= 4;
                case 2: block[1] = aad[1]; remain++; aad_len -= 4;
                case 1: block[0] = aad[0]; remain++; aad_len -= 4;
                }
                block[remain] = aad[remain] & (1 << (8 * aad_len)) - 1;
            } else {
                block[0] = aad[0];
                block[1] = aad[1];
                block[2] = aad[2];
                block[3] = aad[3];
            }
            block[4] = 0x01;

            bytes -= 16;
            aad_len -= 16;
            aad += 4;
        } else if (bytes > 16) {
            if (bytes - 16 <= 16) {
                int remain = 0;
                switch (msg_len >> 2) {
                case 3: block[2] = cipher[2]; remain++; msg_len -= 4;
                case 2: block[1] = cipher[1]; remain++; msg_len -= 4;
                case 1: block[0] = cipher[0]; remain++; msg_len -= 4;
                }
                block[remain] = cipher[remain] & (1 << (8 * msg_len)) - 1;
            } else {
                block[0] = cipher[0];
                block[1] = cipher[1];
                block[2] = cipher[2];
                block[3] = cipher[3];
            }
            block[4] = 0x01;

            bytes -= 16;
            msg_len -= 16;
            cipher += 4;
        } else {
            block[0] = (uint32_t) aad_length;
            // buf[1] = aad_length >> 32;
            block[1] = 0;
            block[2] = (uint32_t) msg_length;
            // buf[3] = msg_length >> 32;
            block[3] = 0;
            block[4] = 0x01;

            bytes -= 16;
        }

        /* add block */
        buf0 = acc0 + block[0];
        buf1 = acc1 + block[1];
        buf2 = acc2 + block[2];
        buf3 = acc3 + block[3];
        buf4 = acc4 + block[4];

        buf1 += (buf0 >> 32);
        buf2 += (buf1 >> 32);
        buf3 += (buf2 >> 32);
        buf4 += (buf3 >> 32);

        acc0 = (uint32_t) buf0;
        acc1 = (uint32_t) buf1;
        acc2 = (uint32_t) buf2;
        acc3 = (uint32_t) buf3;
        acc4 = (uint32_t) buf4;

        /* multiply r */
        /* compute acc * r */
        buf0 = (uint64_t) acc0 * r0 +
                 (uint64_t) 5 * acc1 * (r3 >> 2) + (uint64_t) 5 * acc2 * (r2 >> 2) + (uint64_t) 5 * acc3 * (r1 >> 2) + (uint64_t) 5 * acc4 * (r0 >> 2);
        buf1 = (uint64_t) acc0 * r1 + (uint64_t) acc1 * r0 +
                 (uint64_t) 5 * acc2 * (r3 >> 2) + (uint64_t) 5 * acc3 * (r2 >> 2) + (uint64_t) 5 * acc4 * (r1 >> 2);
        buf2 = (uint64_t) acc0 * r2 + (uint64_t) acc1 * r1 + (uint64_t) acc2 * r0 +
                 (uint64_t) 5 * acc3 * (r3 >> 2) + (uint64_t) 5 * acc4 * (r2 >> 2);
        buf3 = (uint64_t) acc0 * r3 + (uint64_t) acc1 * r2 + (uint64_t) acc2 * r1 + (uint64_t) acc3 * r0 +
                 (uint64_t) 5 * acc4 * (r3 >> 2);

        /* compute carry */
        buf4 = acc4 * (r0 & 3) + (buf3 >> 32);
        carry = 5 * (buf4 >> 2);
        carry += (uint32_t) buf0;                  acc0 = (uint32_t) carry; carry >>= 32;
        carry += (uint32_t) buf1 + (buf0 >> 32); acc1 = (uint32_t) carry; carry >>= 32;
        carry += (uint32_t) buf2 + (buf1 >> 32); acc2 = (uint32_t) carry; carry >>= 32;
        carry += (uint32_t) buf3 + (buf2 >> 32); acc3 = (uint32_t) carry; carry >>= 32;
        carry += (buf4 & 3);              acc4 = (uint32_t) carry;
    }

    /* add s */
    /* if 2^130 -5 < acc < 2^130 then acc = acc - (2^130 - 5) */
    carry = 5;
    carry += (uint64_t) acc0; carry >>= 32;
    carry += (uint64_t) acc1; carry >>= 32;
    carry += (uint64_t) acc2; carry >>= 32;
    carry += (uint64_t) acc3; carry >>= 32;
    carry += (uint64_t) acc4;
    carry = 5 * (carry >> 2);   // carry > 0 then acc > 2^130 - 5

    /* add "s" to "acc" */
    buf0 = (uint64_t) acc0 + ps0;
    buf1 = (uint64_t) acc1 + ps1;
    buf2 = (uint64_t) acc2 + ps2;
    buf3 = (uint64_t) acc3 + ps3;
    buf4 = (uint64_t) acc4;

    buf1 += (buf0 >> 32);
    buf2 += (buf1 >> 32);
    buf3 += (buf2 >> 32);
    buf4 += (buf3 >> 32);

    acc0 = (uint32_t) buf0;
    acc1 = (uint32_t) buf1;
    acc2 = (uint32_t) buf2;
    acc3 = (uint32_t) buf3;
    acc4 = (uint32_t) buf4;

    /* compute carry */
    buf0 = acc0 + carry;
    buf1 = acc1 + (buf0 >> 32);
    buf2 = acc2 + (buf1 >> 32);
    buf3 = acc3 + (buf2 >> 32);

    acc0 = (uint32_t) buf0;
    acc1 = (uint32_t) buf1;
    acc2 = (uint32_t) buf2;
    acc3 = (uint32_t) buf3;

    /* returning tag */
    tag[0] = acc0;
    tag[1] = acc1;
    tag[2] = acc2;
    tag[3] = acc3;
}
