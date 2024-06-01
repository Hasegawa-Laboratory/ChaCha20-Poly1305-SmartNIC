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
void poly1305_mac(__mem40 uint32_t *msg, int len, uint32_t *key, __mem40 uint32_t *tag);

__shared __cls32 uint8_t key[32] = {
    0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a,
    0x0b, 0x0c, 0x0d, 0x0e, 0x0f, 0x10, 0x11, 0x12, 0x13, 0x14, 0x15,
    0x16, 0x17, 0x18, 0x19, 0x1a, 0x1b, 0x1c, 0x1d, 0x1e, 0x1f,
};

int main(void) {
    __xread struct nbi_meta_catamaran nbi_meta;
    __mem40 uint8_t *pkt;
    int offset = MAC_PREPEND_BYTES * 2 + NET_ETH_LEN;

    for (;;) {
        pkt = receive_packet(&nbi_meta);
        poly1305_mac((__mem40 uint32_t *)(pkt + offset), nbi_meta.pkt_info.len - offset, (uint32_t *)key, (__mem40 uint32_t *)(pkt + offset));
        send_packet(&nbi_meta);
    }

    return 0;
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

void poly1305_mac(__mem40 uint32_t *msg, int len, uint32_t *key, __mem40 uint32_t *tag) {
    __gpr uint32_t acc0 = 0, acc1 = 0, acc2 = 0, acc3 = 0, acc4 = 0;
    __lmem uint32_t r0, r1, r2, r3, s0, s1, s2, s3;
    __lmem uint64_t block[5];
    __gpr uint64_t buf0, buf1, buf2, buf3, buf4;
    __lmem uint64_t carry;

    r0 = key[0] & 0x0fffffff;
    r1 = key[1] & 0x0ffffffc;
    r2 = key[2] & 0x0ffffffc;
    r3 = key[3] & 0x0ffffffc;
    s0 = key[4];
    s1 = key[5];
    s2 = key[6];
    s3 = key[7];

    for (;;) {
        /* make block */
        if (len <= 0) break;
        if (len < 16) {
            int remain = 0;
            block[0] = 0;
            block[1] = 0;
            block[2] = 0;
            block[3] = 0;
            block[4] = 0;
            switch (len >> 2) {
                case 3: block[2] = msg[2]; remain++; len -= 4;
                case 2: block[1] = msg[1]; remain++; len -= 4;
                case 1: block[0] = msg[0]; remain++; len -= 4;
            }
            block[remain] = 0x01 << (8 * len) | (msg[remain] & (1 << (8 * len)) - 1);
        } else {
            block[0] = msg[0];
            block[1] = msg[1];
            block[2] = msg[2];
            block[3] = msg[3];
            block[4] = 0x01;
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
        carry += (uint32_t) buf0;                acc0 = (uint32_t) carry; carry >>= 32;
        carry += (uint32_t) buf1 + (buf0 >> 32); acc1 = (uint32_t) carry; carry >>= 32;
        carry += (uint32_t) buf2 + (buf1 >> 32); acc2 = (uint32_t) carry; carry >>= 32;
        carry += (uint32_t) buf3 + (buf2 >> 32); acc3 = (uint32_t) carry; carry >>= 32;
        carry += (buf4 & 3);                     acc4 = (uint32_t) carry;

        len -= 16;
        msg += 4;
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
    buf0 = (uint64_t) acc0 + s0;
    buf1 = (uint64_t) acc1 + s1;
    buf2 = (uint64_t) acc2 + s2;
    buf3 = (uint64_t) acc3 + s3;
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
