#[macro_use]
extern crate clap;
#[macro_use]
extern crate log;
extern crate pretty_env_logger;

use std::net::UdpSocket;

use pcap::Capture;

fn start_mirror(dns_ip_str: &str, sniff_dev: &str) {
    let mut cap = Capture::from_device(sniff_dev)
        .unwrap()
        .immediate_mode(true)
        .promisc(true)
        .open()
        .unwrap();
    let cap_filter = format!("udp dst port 53 and host not {}", dns_ip_str);
    cap.filter(&cap_filter, true).unwrap();

    let socket = UdpSocket::bind("192.168.2.1:34254").expect("Couldn't create UDP socket");
    let remote_socket = format!("{}:53", dns_ip_str);

    loop {
        let packet_data = cap.next().unwrap().data;

        let (body, _) = pktparse::ethernet::parse_ethernet_frame(packet_data).unwrap();
        let (body, ip_header) = pktparse::ipv4::parse_ipv4_header(body).unwrap();
        let (body, _) = pktparse::udp::parse_udp_header(body).unwrap();

        debug!(
            "Dns from {:?} mirrored to {}",
            ip_header.source_addr, dns_ip_str
        );

        socket
            .send_to(body, &remote_socket)
            .unwrap_or_else(|_| panic!("This could never happen since UDP proto is stateless"));
    }
}

fn main() {
    let matches = clap_app!(myapp =>
        (name: "DNS traffic mirroring daemon")
        (version: "0.1.0")
        (@arg dev: +required -d --dev +takes_value "Device to sniff")
        (@arg ip: +required -i --ip +takes_value "DNS server IP")
        (@arg verbose: --verbose "Show debug messages")
    )
    .get_matches();
    let ip_addr = matches.value_of("ip").unwrap();
    let dev = matches.value_of("dev").unwrap();
    if matches.is_present("verbose"){
        pretty_env_logger::formatted_timed_builder()
            .parse_filters("debug")
            .init();
    }
    start_mirror(ip_addr, dev);
}
