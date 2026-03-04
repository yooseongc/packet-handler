use std::net::IpAddr;

use anyhow::{bail, Result};
use pnet_packet::{
    ethernet::{EtherTypes, MutableEthernetPacket},
    ip::IpNextHeaderProtocols,
    ipv4::{checksum as ipv4_header_checksum, MutableIpv4Packet},
    ipv6::MutableIpv6Packet,
    tcp::{ipv4_checksum as tcp_ipv4_checksum, ipv6_checksum as tcp_ipv6_checksum, MutableTcpPacket},
    udp::{ipv4_checksum as udp_ipv4_checksum, ipv6_checksum as udp_ipv6_checksum, MutableUdpPacket},
    MutablePacket,
};

use crate::cli::{Cli, Commands};

pub fn transform_packet(mut data: Vec<u8>, cli: &Cli) -> Result<(Vec<u8>, bool, bool)> {
    let mut changed = false;
    let mut truncated = false;

    match &cli.command {
        Commands::SubstituteIp { from, to } => {
            changed = substitute_ip(&mut data, *from, *to, cli.ignore_checksum)?;
        }
        Commands::Snaplen { n } => {
            if *n == 0 {
                bail!("snaplen must be > 0");
            }
            if data.len() > *n {
                data.truncate(*n);
                truncated = true;
            }
        }
    }

    Ok((data, changed, truncated))
}

fn substitute_ip(packet: &mut [u8], from: IpAddr, to: IpAddr, ignore_checksum: bool) -> Result<bool> {
    if let Some(mut eth) = MutableEthernetPacket::new(packet) {
        match eth.get_ethertype() {
            EtherTypes::Ipv4 => {
                let payload = eth.payload_mut();
                return substitute_ipv4(payload, from, to, ignore_checksum);
            }
            EtherTypes::Ipv6 => {
                let payload = eth.payload_mut();
                return substitute_ipv6(payload, from, to, ignore_checksum);
            }
            _ => {}
        }
    }

    if let Ok(changed) = substitute_ipv4(packet, from, to, ignore_checksum) {
        if changed {
            return Ok(true);
        }
    }
    if let Ok(changed) = substitute_ipv6(packet, from, to, ignore_checksum) {
        if changed {
            return Ok(true);
        }
    }

    Ok(false)
}

fn substitute_ipv4(buf: &mut [u8], from: IpAddr, to: IpAddr, ignore_checksum: bool) -> Result<bool> {
    let (from, to) = match (from, to) {
        (IpAddr::V4(f), IpAddr::V4(t)) => (f, t),
        _ => return Ok(false),
    };

    let mut ip = match MutableIpv4Packet::new(buf) {
        Some(p) => p,
        None => return Ok(false),
    };

    let mut changed = false;
    if ip.get_source() == from {
        ip.set_source(to);
        changed = true;
    }
    if ip.get_destination() == from {
        ip.set_destination(to);
        changed = true;
    }

    if changed && !ignore_checksum {
        ip.set_checksum(0);
        let csum = ipv4_header_checksum(&ip.to_immutable());
        ip.set_checksum(csum);

        let proto = ip.get_next_level_protocol();
        let src = ip.get_source();
        let dst = ip.get_destination();
        let payload = ip.payload_mut();

        match proto {
            IpNextHeaderProtocols::Tcp => {
                if let Some(mut tcp) = MutableTcpPacket::new(payload) {
                    tcp.set_checksum(0);
                    let csum = tcp_ipv4_checksum(&tcp.to_immutable(), &src, &dst);
                    tcp.set_checksum(csum);
                }
            }
            IpNextHeaderProtocols::Udp => {
                if let Some(mut udp) = MutableUdpPacket::new(payload) {
                    udp.set_checksum(0);
                    let csum = udp_ipv4_checksum(&udp.to_immutable(), &src, &dst);
                    udp.set_checksum(csum);
                }
            }
            _ => {}
        }
    }

    Ok(changed)
}

fn substitute_ipv6(buf: &mut [u8], from: IpAddr, to: IpAddr, ignore_checksum: bool) -> Result<bool> {
    let (from, to) = match (from, to) {
        (IpAddr::V6(f), IpAddr::V6(t)) => (f, t),
        _ => return Ok(false),
    };

    let mut ip = match MutableIpv6Packet::new(buf) {
        Some(p) => p,
        None => return Ok(false),
    };

    let mut changed = false;
    if ip.get_source() == from {
        ip.set_source(to);
        changed = true;
    }
    if ip.get_destination() == from {
        ip.set_destination(to);
        changed = true;
    }

    if changed && !ignore_checksum {
        let next = ip.get_next_header();
        let src = ip.get_source();
        let dst = ip.get_destination();
        let payload = ip.payload_mut();

        match next {
            IpNextHeaderProtocols::Tcp => {
                if let Some(mut tcp) = MutableTcpPacket::new(payload) {
                    tcp.set_checksum(0);
                    let csum = tcp_ipv6_checksum(&tcp.to_immutable(), &src, &dst);
                    tcp.set_checksum(csum);
                }
            }
            IpNextHeaderProtocols::Udp => {
                if let Some(mut udp) = MutableUdpPacket::new(payload) {
                    udp.set_checksum(0);
                    let csum = udp_ipv6_checksum(&udp.to_immutable(), &src, &dst);
                    udp.set_checksum(csum);
                }
            }
            _ => {}
        }
    }

    Ok(changed)
}
