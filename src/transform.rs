use std::{collections::HashMap, net::IpAddr};

use anyhow::{Result, anyhow, bail};
use pnet_packet::{
    MutablePacket,
    ethernet::{EtherTypes, MutableEthernetPacket},
    ip::IpNextHeaderProtocols,
    ipv4::{MutableIpv4Packet, checksum as ipv4_header_checksum},
    ipv6::MutableIpv6Packet,
    tcp::{
        MutableTcpPacket, ipv4_checksum as tcp_ipv4_checksum, ipv6_checksum as tcp_ipv6_checksum,
    },
    udp::{
        MutableUdpPacket, ipv4_checksum as udp_ipv4_checksum, ipv6_checksum as udp_ipv6_checksum,
    },
};

use crate::cli::{Cli, Commands};

pub fn transform_packet(mut data: Vec<u8>, cli: &Cli) -> Result<(Vec<u8>, bool, bool)> {
    let mut changed = false;
    let mut truncated = false;

    match &cli.command {
        Commands::SubstituteIp { maps } => {
            let map = parse_ip_maps(maps)?;
            changed = substitute_ip_multi(&mut data, &map, cli.ignore_checksum)?;
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
        _ => {}
    }

    Ok((data, changed, truncated))
}

fn parse_ip_maps(raw: &[String]) -> Result<HashMap<IpAddr, IpAddr>> {
    let mut out = HashMap::new();
    for m in raw {
        let (lhs, rhs) = m
            .split_once('=')
            .ok_or_else(|| anyhow!("invalid --map format (expected A=B): {m}"))?;
        let from: IpAddr = lhs.parse().map_err(|_| anyhow!("invalid from ip: {lhs}"))?;
        let to: IpAddr = rhs.parse().map_err(|_| anyhow!("invalid to ip: {rhs}"))?;

        match (from, to) {
            (IpAddr::V4(_), IpAddr::V4(_)) | (IpAddr::V6(_), IpAddr::V6(_)) => {}
            _ => bail!("ip version mismatch in map: {m}"),
        }

        out.insert(from, to);
    }
    Ok(out)
}

fn substitute_ip_multi(
    packet: &mut [u8],
    map: &HashMap<IpAddr, IpAddr>,
    ignore_checksum: bool,
) -> Result<bool> {
    if let Some(mut eth) = MutableEthernetPacket::new(packet) {
        match eth.get_ethertype() {
            EtherTypes::Ipv4 => {
                let payload = eth.payload_mut();
                return substitute_ipv4(payload, map, ignore_checksum);
            }
            EtherTypes::Ipv6 => {
                let payload = eth.payload_mut();
                return substitute_ipv6(payload, map, ignore_checksum);
            }
            _ => {}
        }
    }

    if let Ok(changed) = substitute_ipv4(packet, map, ignore_checksum) {
        if changed {
            return Ok(true);
        }
    }
    if let Ok(changed) = substitute_ipv6(packet, map, ignore_checksum) {
        if changed {
            return Ok(true);
        }
    }

    Ok(false)
}

fn substitute_ipv4(
    buf: &mut [u8],
    map: &HashMap<IpAddr, IpAddr>,
    ignore_checksum: bool,
) -> Result<bool> {
    let mut ip = match MutableIpv4Packet::new(buf) {
        Some(p) => p,
        None => return Ok(false),
    };

    let mut changed = false;
    let src = IpAddr::V4(ip.get_source());
    if let Some(IpAddr::V4(to)) = map.get(&src) {
        ip.set_source(*to);
        changed = true;
    }

    let dst = IpAddr::V4(ip.get_destination());
    if let Some(IpAddr::V4(to)) = map.get(&dst) {
        ip.set_destination(*to);
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

fn substitute_ipv6(
    buf: &mut [u8],
    map: &HashMap<IpAddr, IpAddr>,
    ignore_checksum: bool,
) -> Result<bool> {
    let mut ip = match MutableIpv6Packet::new(buf) {
        Some(p) => p,
        None => return Ok(false),
    };

    let mut changed = false;
    let src = IpAddr::V6(ip.get_source());
    if let Some(IpAddr::V6(to)) = map.get(&src) {
        ip.set_source(*to);
        changed = true;
    }

    let dst = IpAddr::V6(ip.get_destination());
    if let Some(IpAddr::V6(to)) = map.get(&dst) {
        ip.set_destination(*to);
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
