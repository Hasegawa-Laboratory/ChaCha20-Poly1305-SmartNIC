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
void chacha20_encrypt(uint32_t *key, uint32_t *nonce, uint32_t counter,
                      __mem40 uint32_t *plaintext, __mem40 uint32_t *ciphertext, int bytes);

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

int main(void) {
    __xread struct nbi_meta_catamaran nbi_meta;
    __mem40 uint8_t *pkt;
    int offset = MAC_PREPEND_BYTES * 2 + NET_ETH_LEN;

    for (;;) {
        pkt = receive_packet(&nbi_meta);
        chacha20_encrypt((uint32_t *)key, (uint32_t *)nonce, 1,
                         (__mem40 uint32_t *)(pkt+offset), (__mem40 uint32_t *)(pkt+offset), nbi_meta.pkt_info.len - offset);
        send_packet(&nbi_meta);
    }

    return 0;
}

uint32_t byte_swap(uint32_t x) {
    return (x & 0x000000ff) << 24 | (x & 0x0000ff00) << 8 |
           (x & 0x00ff0000) >> 8  | (x & 0xff000000) >> 24;
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
    q_dst = PORT_TO_CHANNEL(nbi_meta->port == 3 ? 19 : 3);

    msi = pkt_msd_write(pbuf, pkt_off - MAC_PREPEND_BYTES);
    pkt_nbi_send(island, pnum, &msi, plen, NBI, q_dst, nbi_meta->seqr,
                 nbi_meta->seq, PKT_CTM_SIZE_256);
}

void chacha20_encrypt(uint32_t *key, uint32_t *nonce, uint32_t counter,
                      __mem40 uint32_t *plaintext, __mem40 uint32_t *ciphertext, int bytes) {
    __lmem uint32_t s0, s1, s2, s3, s4, s5, s6, s7, s8, s9, s10, s11, s12, s13,
        s14, s15;
    __gpr uint32_t a0, a1, a2, a3, a4, a5, a6, a7, a8, a9, a10, a11, a12, a13,
        a14, a15;
    int i;

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
    s12 = counter;
    s13 = nonce[0];
    s14 = nonce[1];
    s15 = nonce[2];

    for (;;) {
        if (bytes <= 0) return;
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

        if (bytes < 61) {
            switch ((bytes - 1) >> 2) {
                case 14:
                    ciphertext[14] = byte_swap(a14) ^ plaintext[14];
                case 13:
                    ciphertext[13] = byte_swap(a13) ^ plaintext[13];
                case 12:
                    ciphertext[12] = byte_swap(a12) ^ plaintext[12];
                case 11:
                    ciphertext[11] = byte_swap(a11) ^ plaintext[11];
                case 10:
                    ciphertext[10] = byte_swap(a10) ^ plaintext[10];
                case 9:
                    ciphertext[9] = byte_swap(a9) ^ plaintext[9];
                case 8:
                    ciphertext[8] = byte_swap(a8) ^ plaintext[8];
                case 7:
                    ciphertext[7] = byte_swap(a7) ^ plaintext[7];
                case 6:
                    ciphertext[6] = byte_swap(a6) ^ plaintext[6];
                case 5:
                    ciphertext[5] = byte_swap(a5) ^ plaintext[5];
                case 4:
                    ciphertext[4] = byte_swap(a4) ^ plaintext[4];
                case 3:
                    ciphertext[3] = byte_swap(a3) ^ plaintext[3];
                case 2:
                    ciphertext[2] = byte_swap(a2) ^ plaintext[2];
                case 1:
                    ciphertext[1] = byte_swap(a1) ^ plaintext[1];
                case 0:
                    ciphertext[0] = byte_swap(a0) ^ plaintext[0];
            }
            return;
        }

        ciphertext[0] = byte_swap(a0) ^ plaintext[0];
        ciphertext[1] = byte_swap(a1) ^ plaintext[1];
        ciphertext[2] = byte_swap(a2) ^ plaintext[2];
        ciphertext[3] = byte_swap(a3) ^ plaintext[3];
        ciphertext[4] = byte_swap(a4) ^ plaintext[4];
        ciphertext[5] = byte_swap(a5) ^ plaintext[5];
        ciphertext[6] = byte_swap(a6) ^ plaintext[6];
        ciphertext[7] = byte_swap(a7) ^ plaintext[7];
        ciphertext[8] = byte_swap(a8) ^ plaintext[8];
        ciphertext[9] = byte_swap(a9) ^ plaintext[9];
        ciphertext[10] = byte_swap(a10) ^ plaintext[10];
        ciphertext[11] = byte_swap(a11) ^ plaintext[11];
        ciphertext[12] = byte_swap(a12) ^ plaintext[12];
        ciphertext[13] = byte_swap(a13) ^ plaintext[13];
        ciphertext[14] = byte_swap(a14) ^ plaintext[14];
        ciphertext[15] = byte_swap(a15) ^ plaintext[15];

        s12++;

        bytes -= 64;
        plaintext += 16;
        ciphertext += 16;
    }
}
