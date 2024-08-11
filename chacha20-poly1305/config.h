#ifndef __APP_CONFIG_H__
#define __APP_CONFIG_H__

/*
 * RX/TX configuration
 * - Configure RX checksum offload so the wire can validate checksums
 */
#define CFG_RX_CSUM_PREPEND
#define PKT_NBI_OFFSET 64
#define MAC_PREPEND_BYTES 4

/*
 * Mapping between channel and TM queue
 */
enum port_type {
    PKT_PTYPE_DROP = 0,
    PKT_PTYPE_WIRE = 1,
    PKT_PTYPE_HOST = 2,
    PKT_PTYPE_WQ = 3,
    PKT_PTYPE_NONE = 4
};

#define PKT_SET_PORT(type, subsys, port) \
    ((type) << 13) | ((subsys) << 10) | ((port))

#define PKT_WIRE_PORT(_nbi, _q) PKT_SET_PORT(PKT_PTYPE_WIRE, (_nbi), (_q))

#define PORT_TO_CHANNEL(x) ((x) << 3)

#define PKTIO_MAX_TM_QUEUES 256
#define PKT_PORT_QUEUE_of(_port) ((_port) & ((PKTIO_MAX_TM_QUEUES)-1))

#endif /* __APP_CONFIG_H__ */
