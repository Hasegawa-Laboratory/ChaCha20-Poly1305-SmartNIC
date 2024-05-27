#include <net/eth.h>
#include <nfp.h>
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

__mem40 uint8_t *receive_packet(__xread struct nbi_meta_catamaran *nbi_meta);
void send_packet(__xread struct nbi_meta_catamaran *nbi_meta);

int main(void) {
    __xread struct nbi_meta_catamaran nbi_meta;
    __mem40 uint8_t *pkt;

    for (;;) {
        pkt = receive_packet(&nbi_meta);
        send_packet(&nbi_meta);
    }

    return 0;
}

__mem40 uint8_t *receive_packet(__xread struct nbi_meta_catamaran *nbi_meta) {
    int island, pnum, pkt_off;
    __mem40 uint8_t *pkt_hdr;

    pkt_nbi_recv(nbi_meta, sizeof(struct nbi_meta_catamaran));

    pkt_off  = PKT_NBI_OFFSET;
    island   = nbi_meta->pkt_info.isl;
    pnum     = nbi_meta->pkt_info.pnum;

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
    pkt_mac_egress_cmd_write(pbuf, pkt_off, 1, 1);

    /* Set egress tm queue */
    q_dst = PORT_TO_CHANNEL(nbi_meta->port);

    msi = pkt_msd_write(pbuf, pkt_off - MAC_PREPEND_BYTES);
    pkt_nbi_send(island, pnum, &msi, plen, NBI, q_dst, nbi_meta->seqr,
                 nbi_meta->seq, PKT_CTM_SIZE_256);
}
