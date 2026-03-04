use std::{
    fs::File,
    path::{Path, PathBuf},
};

use anyhow::{anyhow, bail, Context, Result};
use pcap_file::{
    pcap::{PcapPacket, PcapReader, PcapWriter},
    pcapng::{Block, PcapNgReader, PcapNgWriter},
};

use crate::{cli::Cli, transform::transform_packet};

pub fn run(cli: &Cli) -> Result<()> {
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

    match extension_of(&cli.input)?.as_str() {
        "pcap" => process_pcap(cli, &output),
        "pcapng" => process_pcapng(cli, &output),
        ext => bail!("unsupported input format: {ext}"),
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
    let input =
        File::open(&cli.input).with_context(|| format!("open input: {}", cli.input.display()))?;
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
    let input =
        File::open(&cli.input).with_context(|| format!("open input: {}", cli.input.display()))?;
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
