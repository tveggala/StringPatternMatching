control Ingress(
    inout ingress_headers_t                       hdr,
    inout ingress_metadata_t                      meta,
    in    ingress_intrinsic_metadata_t               ig_intr_md,
    in    ingress_intrinsic_metadata_from_parser_t   ig_prsr_md,
    inout ingress_intrinsic_metadata_for_deparser_t  ig_dprsr_md,
    inout ingress_intrinsic_metadata_for_tm_t        ig_tm_md)
{
    bit<8>  let_it_go_register_value=0;
    bit<16> let_it_go_register_key=0;
    bit<8>  protocol_exemption = 0;
    bit<16> port_value=0;
    bit<8>  accept_state_flag=7;
    bit<2>  fsm_flag=0;

    Register<bit<8>, bit<16>>(size=16384*35,initial_value=7)  let_it_go_register;
    RegisterAction<bit<8>, bit<16>, bit<8>>(let_it_go_register) let_it_go_read = {
        void apply(inout bit<8> reg_value, out bit<8> result) {
            result = reg_value;
        }
    };
    RegisterAction<bit<8>, bit<16>, bit<8>>(let_it_go_register) let_it_go_recir = {
        void apply(inout bit<8> reg_value) {
           reg_value = RECIRCULATE;
        }
    };
    RegisterAction<bit<8>, bit<16>, bit<8>>(let_it_go_register) let_it_go_accept = {
        void apply(inout bit<8> reg_value) {
            reg_value = ACCEPT;
        }
    };
    RegisterAction<bit<8>, bit<16>, bit<8>>(let_it_go_register) let_it_go_reject = {
        void apply(inout bit<8> reg_value) {
            reg_value = REJECT;
        }
    };
    Hash<bit<16>>(HashAlgorithm_t.CRC16) hash_1;

    action route(PortId_t port) {
        ig_tm_md.ucast_egress_port = port;
        ig_dprsr_md.drop_ctl = 0;
    }
    action nop() {}
    action drop() {
        ig_dprsr_md.drop_ctl = 0x1; // Drop packet.
    }
    action do_recirculate() {
        ig_tm_md.ucast_egress_port = 68;
    }
    table forward {
        key = {
            hdr.ipv4.dst_addr : lpm;
        }
        actions = {
            route;
            drop;
            nop;
        }
        const default_action = drop;
        size = 1024;
    }
    action increment_count() {
        hdr.recir.count = hdr.recir.count + 1;
    }
    action reset_count() {
        hdr.recir.count = 0;
    }
    table check {
        key = {
            hdr.app.byte : exact;
        }
        actions = {
            increment_count;
            reset_count;
        }
        const default_action = reset_count();
        size = 1024;
    }
    action original_tcp_packet_action() {
        // A. Mirror
        ig_dprsr_md.mirror_type = MIRROR_TYPE_I2E;
        meta.ing_mir_ses = 27;
        meta.PKT_TYPE_MIRROR = 10;
        // B. Recirculate
        do_recirculate();
        // C. Validate recirculated header
        hdr.recir.setValid();
        hdr.recir.packet_state=0;
        hdr.recir.pattern_state_machine_state=0;
        hdr.recir.let_it_go_register_value = RECIRCULATE;
        hdr.recir.current_state = 0; // new recir header state
        // D. Set TCP PORT to RECIRCULAR_PORT
        // Store the TCP port value in port register
        hdr.recir.port_value = hdr.tcp.dst_port;
        hdr.tcp.dst_port = 5555;
        hdr.recir.let_it_go_register_value = let_it_go_recir.execute(let_it_go_register_key); // initialize letitigo register
        hdr.recir.let_it_go_register_value = RECIRCULATE;
    }
    action original_recirculated_tcp_packet_recirculate_action() {
        // Check result of the clone packet from let_it_go_register
        hdr.recir.let_it_go_register_value = let_it_go_read.execute(let_it_go_register_key);
        do_recirculate();
    }
    action original_recirculated_tcp_packet_accept_action() {
        hdr.tcp.dst_port = hdr.recir.port_value;
        hdr.recir.setInvalid();
    }
    action original_recirculated_tcp_packet_reject_action() {
        drop();
    }
    action recirculated_mirrored_tcp_packet_recirculate_action() {
        fsm_flag = 1;
    }
    action recirculated_mirrored_tcp_packet_accept_action() {
        let_it_go_accept.execute(let_it_go_register_key);
        drop();
    }
    action recirculated_mirrored_tcp_packet_reject_action() {
        let_it_go_reject.execute(let_it_go_register_key);
        drop();
    }
    table first_level_table {
        key = {
            hdr.tcp.isValid():exact;
            hdr.app.isValid():exact;
            hdr.recir.isValid():exact;
            hdr.recir.packet_state:ternary;
            hdr.recir.let_it_go_register_value:ternary;
            ig_prsr_md.parser_err:ternary;
        }
        actions = {
            original_tcp_packet_action;
            original_recirculated_tcp_packet_recirculate_action;
            original_recirculated_tcp_packet_accept_action;
            original_recirculated_tcp_packet_reject_action;
            recirculated_mirrored_tcp_packet_recirculate_action;
            recirculated_mirrored_tcp_packet_accept_action;
            recirculated_mirrored_tcp_packet_reject_action;
            nop;
        }
        const entries = {
            (true,      true,   false,  _,      _, _) : original_tcp_packet_action();
            (true,      true,   true,   10,     RECIRCULATE, 0x0022) : recirculated_mirrored_tcp_packet_accept_action();
            (true,      true,   true,   1,      RECIRCULATE, _) : original_recirculated_tcp_packet_recirculate_action();
            (true,      true,   true,   1,      ACCEPT, _) : original_recirculated_tcp_packet_accept_action();
            (true,      true,   true,   1,      REJECT, _) : original_recirculated_tcp_packet_reject_action();
            (true,      true,   true,   10,     RECIRCULATE, _) : recirculated_mirrored_tcp_packet_recirculate_action();
            (true,      true,   true,   10,     REJECT, _) : recirculated_mirrored_tcp_packet_reject_action();
            (true,      false,  true,   10,     REJECT, _) : recirculated_mirrored_tcp_packet_reject_action();
        }
        const default_action = nop();
        size = 1024;
    }
    apply {
        if (hdr.ipv4.isValid()) {
            if (!(hdr.tcp.isValid() &&
                  hdr.app.isValid() &&
                  hdr.recir.packet_state == 1 &&
                  hdr.recir.let_it_go_register_value == 5))
            forward.apply();
            if (hdr.tcp.isValid()) {
                let_it_go_register_key = hash_1.get(
                {
                 hdr.tcp.checksum,   
                 hdr.ipv4.total_len, 
                 hdr.ipv4.src_addr,  
                 hdr.ipv4.dst_addr,
                 hdr.tcp.src_port,   
                 hdr.tcp.dst_port,   
                 hdr.ipv4.identification,
                 hdr.ipv4.protocol,
                 hdr.tcp.seq_no,
                 hdr.tcp.ack_no
                })[15:0];
            }
            first_level_table.apply();
            if (hdr.recir.count <= 20) {
                hdr.recir.let_it_go_register_value = accept_state_flag;
                drop();
            }
            if (fsm_flag == 1) {
                check.apply();
                do_recirculate();
            }
       }
    }
}
