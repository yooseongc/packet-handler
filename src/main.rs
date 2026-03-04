use std::{
    fs::File,
    net::IpAddr,
    path::{Path, PathBuf},
};

use anyhow::{anyhow, bail, Context, Result};
use clap::{Parser, Subcommand};
use pcap_file::{
    pcap::{PcapPacket, PcapReader, PcapWriter},
    pcapng::{Block, PcapNgReader, PcapNgWriter},
};
use pnet_packet::{
    ethernet::{EtherTypes, MutableEthernetPacket},
    ip::IpNextHeaderProtocols,
    ipv4::{checksum as ipv4_header_checksum, MutableIpv4Packet},
    ipv6::MutableIpv6Packet,
    tcp::{ipv4_checksum as tcp_ipv4_checksum, ipv6_checksum as tcp_ipv6_checksum, MutableTcpPacket},
    udp::{ipv4_checksum as udp_ipv4_checksum, ipv6_checksum as udp_ipv6_checksum, MutableUdpPacket},
    MutablePacket,
};

#[derive(Parser, Debug)]
#[command(name = "packet_handler")]
struct Cli {
    #[arg(long)]
    input: PathBuf,

    #[arg(long)]
    output: Option<PathBuf>,

    #[arg(long, default_value_t = false)]
    ignore_checksum: bool,

    #[arg(long, default_value_t = false)]
    overwrite: bool,

    #[command(subcommand)]
    command: Commands,
}

#[derive(Subcommand, Debug)]
enum Commands {
    #[command(name = "substitute_ip")]
    SubstituteIp {
        #[arg(long)]
        from: IpAddr,
        #[arg(long)]
        to: IpAddr,
    },
    Snaplen {
        n: usize,
    },
}

fn main() -> Result<()> {
    let cli = Cli::parse();

    if !cli.input.exists() {
        bail!("input file does not exist: {}", cli.input.display());
    }

    let output = resolve_output_path(&cli.input, cli.output.clone());
    if output.exists() && !cli.overwrite {
        bail!(
            "output already exists (use --overwrite): {}",
            output.display()
        );
    }

    let input_ext = extension_of(&cli.input)?;
    match input_ext.as_str() {
        "pcap" => process_pcap(&cli, &output),
        "pcapng" => process_pcapng(&cli, &output),
        _ => bail!("unsupported input format: {input_ext}"),
    }
}

fn resolve_output_path(input: &Path, output: Option<PathBuf>) -> PathBuf {
    if let Some(out) = output {
        return out;
    }

    let cwd = std::env::current_dir().unwrap_or_else(|_| PathBuf::from("."));
    let stem = input
        .file_stem()
        .and_then(|s| s.to_str())
        .unwrap_or("output");
    let ext = input
        .extension()
        .and_then(|s| s.to_str())
        .unwrap_or("pcap");
    cwd.join(format!("{stem}.out.{ext}"))
}

fn extension_of(path: &Path) -> Result<String> {
    path.extension()
        .and_then(|e| e.to_str())
        .map(|s| s.to_ascii_lowercase())
        .ok_or_else(|| anyhow!("cannot determine extension from {}", path.display()))
}

fn process_pcap(cli: &Cli, output: &Path) -> Result<()> {
    let input = File::open(&cli.input).with_context(|| format!("open input: {}", cli.input.display()))?;
    let mut reader = PcapReader::new(input)?;
    let header = reader.header().clone();

    let out = File::create(output).with_context(|| format!("create output: {}", output.display()))?;
    let mut writer = PcapWriter::with_header(out, header)?;

    let mut total = 0usize;
    let mut changed = 0usize;
    let mut truncated = 0usize;

    while let Some(pkt) = reader.next_packet() {
        let pkt = pkt?;
        total += 1;

        let (new_data, c, t) = transform_packet(pkt.data.to_vec(), cli)?;
        if c {
            changed += 1;
        }
        if t {
            truncated += 1;
        }

        let out_pkt = PcapPacket::new(pkt.timestamp, new_data.len() as u32, &new_data);
        writer.write_packet(&out_pkt)?;
    }

    eprintln!("processed={total}, ip_changed={changed}, truncated={truncated}");
    Ok(())
}

fn process_pcapng(cli: &Cli, output: &Path) -> Result<()> {
    let input = File::open(&cli.input).with_context(|| format!("open input: {}", cli.input.display()))?;
    let mut reader = PcapNgReader::new(input)?;

    let out = File::create(output).with_context(|| format!("create output: {}", output.display()))?;
    let mut writer = PcapNgWriter::new(out)?;

    let mut total = 0usize;
    let mut changed = 0usize;
    let mut truncated = 0usize;

    while let Some(block) = reader.next_block() {
        let mut block = block?;

        if let Block::EnhancedPacket(ref mut epb) = block {
            total += 1;
            let (new_data, c, t) = transform_packet(epb.data.to_vec(), cli)?;
            if c {
                changed += 1;
            }
            if t {
                truncated += 1;
            }
            epb.data = new_data.into();
            epb.original_len = epb.data.len() as u32;
        }

        writer.write_block(&block)?;
    }

    eprintln!("processed={total}, ip_changed={changed}, truncated={truncated}");
    Ok(())
}

fn transform_packet(mut data: Vec<u8>, cli: &Cli) -> Result<(Vec<u8>, bool, bool)> {
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
    // Try Ethernet frame first
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

    // Fallback: raw L3 buffer
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
