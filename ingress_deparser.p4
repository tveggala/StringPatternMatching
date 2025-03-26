control IngressDeparser(packet_out pkt,
    /* User */
    inout ingress_headers_t                       hdr,
    in    ingress_metadata_t                      meta,
    /* Intrinsic */
    in    ingress_intrinsic_metadata_for_deparser_t  ig_dprsr_md)
{
    Mirror() mirror;

    Checksum() ipv4_checksum;
    Checksum() tcp_checksum;
    apply {
        // Mirror (ingress to egress) to recirculate port only for original packet - MirrorId_t
        if (ig_dprsr_md.mirror_type == MIRROR_TYPE_I2E) {
            mirror.emit<mirror_h>(meta.ing_mir_ses,{meta.PKT_TYPE_MIRROR});
        }
        if (hdr.ipv4.isValid()) {
            hdr.ipv4.hdr_checksum = ipv4_checksum.update({
                    hdr.ipv4.version,
                    hdr.ipv4.ihl,
                    hdr.ipv4.diffserv,
                    hdr.ipv4.total_len,
                    hdr.ipv4.identification,
                    hdr.ipv4.flags,
                    hdr.ipv4.frag_offset,
                    hdr.ipv4.ttl,
                    hdr.ipv4.protocol,
                    hdr.ipv4.src_addr,
                    hdr.ipv4.dst_addr
                    });
        }
        if (hdr.tcp.isValid()) {
            hdr.tcp.checksum = tcp_checksum.update({
                    hdr.tcp.src_port,
                    hdr.tcp.dst_port,
                    hdr.tcp.seq_no,
                    hdr.tcp.ack_no,
                    hdr.tcp.data_offset,
                    hdr.tcp.res,
                    hdr.tcp.flags,
                    hdr.tcp.window,
                    hdr.tcp.urgent_ptr
                    });
        }
        pkt.emit(hdr.ethernet);
        pkt.emit(hdr.ipv4);
        pkt.emit(hdr.tcp);
        pkt.emit(hdr.recir);
        pkt.emit(hdr.app);
    }
}
