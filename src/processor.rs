use std::{
    collections::BTreeMap,
    fs::File,
    path::{Path, PathBuf},
    process::Command,
};

use anyhow::{Context, Result, anyhow, bail};
use pcap_file::{
    pcap::{PcapPacket, PcapReader, PcapWriter},
    pcapng::{Block, PcapNgReader, PcapNgWriter},
};

use crate::{
    cli::{AnalyzeLayer, Cli, Commands},
    transform::transform_packet,
};

pub fn run(cli: &Cli) -> Result<()> {
    if !cli.input.exists() {
        bail!("input file does not exist: {}", cli.input.display());
    }

    match &cli.command {
        Commands::Filter { bpf } => run_filter(cli, bpf),
        Commands::Analyze { layer } => run_analyze(cli, layer.clone()),
        _ => run_transform(cli),
    }
}

fn run_transform(cli: &Cli) -> Result<()> {
    let output = resolve_output_path(&cli.input, cli.output.clone());
    if output.exists() && !cli.overwrite {
        bail!(
            "output already exists (use --overwrite): {}",
            output.display()
        );
    }

    match extension_of(&cli.input)?.as_str() {
        "pcap" => process_pcap(cli, &output),
        "pcapng" => process_pcapng(cli, &output),
        ext => bail!("unsupported input format: {ext}"),
    }
}

fn run_filter(cli: &Cli, bpf: &str) -> Result<()> {
    let ext = extension_of(&cli.input)?;
    let output = resolve_output_path(&cli.input, cli.output.clone());
    if output.exists() && !cli.overwrite {
        bail!(
            "output already exists (use --overwrite): {}",
            output.display()
        );
    }

    let input_for_filter = if ext == "pcapng" {
        let tmp = output.with_extension("tmp_filter_input.pcap");
        convert_pcapng_to_pcap_via_tshark(&cli.input, &tmp)?;
        tmp
    } else {
        cli.input.clone()
    };

    let status = Command::new("tcpdump")
        .arg("-r")
        .arg(&input_for_filter)
        .arg("-w")
        .arg(&output)
        .arg(bpf)
        .status()
        .with_context(|| "failed to execute tcpdump for BPF filter")?;

    if ext == "pcapng" {
        let _ = std::fs::remove_file(&input_for_filter);
    }

    if !status.success() {
        bail!("BPF filter failed or invalid syntax: {bpf}");
    }

    eprintln!("filtered output written: {}", output.display());
    Ok(())
}

fn run_analyze(cli: &Cli, layer: AnalyzeLayer) -> Result<()> {
    let text = match layer {
        AnalyzeLayer::Tcp => render_tcp_conversations(&cli.input)?,
        AnalyzeLayer::Icmp => {
            let rows = collect_conversations(&cli.input, &layer)?;
            render_conversations(&cli.input, &layer, &rows)
        }
        _ => {
            let rows = collect_conversations(&cli.input, &layer)?;
            render_conversations(&cli.input, &layer, &rows)
        }
    };

    if let Some(path) = &cli.output {
        if path.exists() && !cli.overwrite {
            bail!(
                "output already exists (use --overwrite): {}",
                path.display()
            );
        }
        std::fs::write(path, text)?;
        eprintln!("analysis output written: {}", path.display());
    } else {
        println!("{text}");
    }

    Ok(())
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
    let ext = input.extension().and_then(|s| s.to_str()).unwrap_or("pcap");
    cwd.join(format!("{stem}.out.{ext}"))
}

fn extension_of(path: &Path) -> Result<String> {
    path.extension()
        .and_then(|e| e.to_str())
        .map(|s| s.to_ascii_lowercase())
        .ok_or_else(|| anyhow!("cannot determine extension from {}", path.display()))
}

fn process_pcap(cli: &Cli, output: &Path) -> Result<()> {
    let input =
        File::open(&cli.input).with_context(|| format!("open input: {}", cli.input.display()))?;
    let mut reader = PcapReader::new(input)?;
    let header = reader.header().clone();

    let out =
        File::create(output).with_context(|| format!("create output: {}", output.display()))?;
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
    let input =
        File::open(&cli.input).with_context(|| format!("open input: {}", cli.input.display()))?;
    let mut reader = PcapNgReader::new(input)?;

    let out =
        File::create(output).with_context(|| format!("create output: {}", output.display()))?;
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

fn collect_conversations(input: &Path, layer: &AnalyzeLayer) -> Result<Vec<(String, u64)>> {
    let (display, fields): (&str, &[&str]) = match layer {
        AnalyzeLayer::Ether => ("ETHER", &["eth.src", "eth.dst"]),
        AnalyzeLayer::Ip => ("IP", &["ip.src", "ip.dst"]),
        AnalyzeLayer::Tcp => ("TCP", &["ip.src", "tcp.srcport", "ip.dst", "tcp.dstport"]),
        AnalyzeLayer::Icmp => ("ICMP", &["ip.src", "ip.dst", "icmp.type", "icmpv6.type"]),
        AnalyzeLayer::Udp => ("UDP", &["ip.src", "udp.srcport", "ip.dst", "udp.dstport"]),
        AnalyzeLayer::Arp => ("ARP", &["arp.src.proto_ipv4", "arp.dst.proto_ipv4"]),
    };

    let mut cmd = Command::new("tshark");
    cmd.arg("-r")
        .arg(input)
        .arg("-T")
        .arg("fields")
        .arg("-E")
        .arg("separator=,");
    for f in fields {
        cmd.arg("-e").arg(f);
    }

    let out = cmd
        .output()
        .with_context(|| format!("failed to execute tshark analyze ({display})"))?;
    if !out.status.success() {
        bail!("analyze failed for layer {display}");
    }

    let mut map: BTreeMap<String, u64> = BTreeMap::new();
    for line in String::from_utf8_lossy(&out.stdout).lines() {
        let cols: Vec<&str> = line.split(',').map(|s| s.trim()).collect();
        if cols.iter().all(|c| c.is_empty()) {
            continue;
        }
        let key = match layer {
            AnalyzeLayer::Ether | AnalyzeLayer::Ip | AnalyzeLayer::Arp => {
                if cols.len() < 2 || cols[0].is_empty() || cols[1].is_empty() {
                    continue;
                }
                format!("{} <-> {}", cols[0], cols[1])
            }
            AnalyzeLayer::Tcp | AnalyzeLayer::Udp => {
                if cols.len() < 4
                    || cols[0].is_empty()
                    || cols[1].is_empty()
                    || cols[2].is_empty()
                    || cols[3].is_empty()
                {
                    continue;
                }
                format!("{}:{} <-> {}:{}", cols[0], cols[1], cols[2], cols[3])
            }
            AnalyzeLayer::Icmp => {
                if cols.len() < 3 || cols[0].is_empty() || cols[1].is_empty() {
                    continue;
                }
                let t = if cols.get(2).map(|v| !v.is_empty()).unwrap_or(false) {
                    cols[2]
                } else if cols.get(3).map(|v| !v.is_empty()).unwrap_or(false) {
                    cols[3]
                } else {
                    "N/A"
                };
                format!("{} <-> {} (type={})", cols[0], cols[1], t)
            }
        };
        *map.entry(key).or_insert(0) += 1;
    }

    let mut rows: Vec<(String, u64)> = map.into_iter().collect();
    rows.sort_by(|a, b| b.1.cmp(&a.1).then_with(|| a.0.cmp(&b.0)));
    Ok(rows)
}

fn render_tcp_conversations(input: &Path) -> Result<String> {
    // src, sport, dst, dport, syn, ack, fin, rst, retransmission
    let out = Command::new("tshark")
        .arg("-r")
        .arg(input)
        .arg("-T")
        .arg("fields")
        .arg("-E")
        .arg("separator=,")
        .arg("-e")
        .arg("ip.src")
        .arg("-e")
        .arg("tcp.srcport")
        .arg("-e")
        .arg("ip.dst")
        .arg("-e")
        .arg("tcp.dstport")
        .arg("-e")
        .arg("tcp.flags.syn")
        .arg("-e")
        .arg("tcp.flags.ack")
        .arg("-e")
        .arg("tcp.flags.fin")
        .arg("-e")
        .arg("tcp.flags.reset")
        .arg("-e")
        .arg("tcp.analysis.retransmission")
        .output()
        .with_context(|| "failed to execute tshark analyze (TCP detailed)")?;
    if !out.status.success() {
        bail!("analyze failed for layer TCP");
    }

    #[derive(Default)]
    struct Stat {
        packets: u64,
        syn: u64,
        ack: u64,
        fin: u64,
        rst: u64,
        retrans: u64,
    }

    let mut map: BTreeMap<String, Stat> = BTreeMap::new();
    for line in String::from_utf8_lossy(&out.stdout).lines() {
        let cols: Vec<&str> = line.split(',').map(|s| s.trim()).collect();
        if cols.len() < 4
            || cols[0].is_empty()
            || cols[1].is_empty()
            || cols[2].is_empty()
            || cols[3].is_empty()
        {
            continue;
        }
        let key = format!("{}:{} <-> {}:{}", cols[0], cols[1], cols[2], cols[3]);
        let st = map.entry(key).or_default();
        st.packets += 1;
        if cols.get(4) == Some(&"1") {
            st.syn += 1;
        }
        if cols.get(5) == Some(&"1") {
            st.ack += 1;
        }
        if cols.get(6) == Some(&"1") {
            st.fin += 1;
        }
        if cols.get(7) == Some(&"1") {
            st.rst += 1;
        }
        if cols.get(8).map(|v| !v.is_empty()).unwrap_or(false) {
            st.retrans += 1;
        }
    }

    let mut rows: Vec<(String, Stat)> = map.into_iter().collect();
    rows.sort_by(|a, b| b.1.packets.cmp(&a.1.packets).then_with(|| a.0.cmp(&b.0)));

    let mut text = String::new();
    text.push_str("packet_handler analyze\n");
    text.push_str(&format!("input: {}\n", input.display()));
    text.push_str("layer: tcp\n");
    text.push_str(&format!("total conversations: {}\n\n", rows.len()));
    text.push_str("  #  packets  state                    retrans  conversation\n");
    text.push_str(
        "---  -------  -----------------------  -------  -----------------------------------\n",
    );

    for (i, (conv, st)) in rows.iter().enumerate() {
        let mut flags = Vec::new();
        if st.syn > 0 {
            flags.push("SYN");
        }
        if st.ack > 0 {
            flags.push("ACK");
        }
        if st.fin > 0 {
            flags.push("FIN");
        }
        if st.rst > 0 {
            flags.push("RST");
        }
        let state = if flags.is_empty() {
            "N/A".to_string()
        } else {
            flags.join("+")
        };

        text.push_str(&format!(
            "{:>3}  {:>7}  {:<23}  {:>7}  {}\n",
            i + 1,
            st.packets,
            state,
            st.retrans,
            conv
        ));
    }

    Ok(text)
}

fn render_conversations(input: &Path, layer: &AnalyzeLayer, rows: &[(String, u64)]) -> String {
    let lname = match layer {
        AnalyzeLayer::Ether => "ether",
        AnalyzeLayer::Ip => "ip",
        AnalyzeLayer::Tcp => "tcp",
        AnalyzeLayer::Icmp => "icmp",
        AnalyzeLayer::Udp => "udp",
        AnalyzeLayer::Arp => "arp",
    };

    let mut out = String::new();
    out.push_str(&format!("packet_handler analyze\n"));
    out.push_str(&format!("input: {}\n", input.display()));
    out.push_str(&format!("layer: {}\n", lname));
    out.push_str(&format!("total conversations: {}\n\n", rows.len()));

    out.push_str("  #  packets  conversation\n");
    out.push_str("---  -------  ---------------------------------------------\n");
    for (i, (conv, count)) in rows.iter().enumerate() {
        out.push_str(&format!("{:>3}  {:>7}  {}\n", i + 1, count, conv));
    }

    out
}

fn convert_pcapng_to_pcap_via_tshark(input_pcapng: &Path, output_pcap: &Path) -> Result<()> {
    let status = Command::new("tshark")
        .arg("-F")
        .arg("pcap")
        .arg("-r")
        .arg(input_pcapng)
        .arg("-w")
        .arg(output_pcap)
        .status()
        .with_context(|| "failed to execute tshark pcapng->pcap conversion")?;

    if !status.success() {
        bail!(
            "pcapng to pcap conversion failed: {}",
            input_pcapng.display()
        );
    }

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::extension_of;
    use std::path::Path;

    #[test]
    fn extension_parse_ok() {
        assert_eq!(extension_of(Path::new("a.pcap")).unwrap(), "pcap");
        assert_eq!(extension_of(Path::new("a.PCAPNG")).unwrap(), "pcapng");
    }
}
