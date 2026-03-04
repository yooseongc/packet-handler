use std::path::PathBuf;

use clap::{Parser, Subcommand, ValueEnum};

#[derive(Parser, Debug)]
#[command(
    name = "packet_handler",
    about = "Process pcap/pcapng files: substitute IPs, truncate snaplen, filter by BPF, and analyze conversations",
    long_about = "packet_handler reads .pcap/.pcapng files and applies one operation per run.\n\nOperations:\n- substitute_ip: replace IPs using one or more --map FROM=TO rules\n- snaplen: truncate packet bytes to N\n- filter: extract packets with a BPF expression (invalid BPF -> fail)\n- analyze: print conversation summaries (ether/ip/tcp/icmp/udp/arp)"
)]
pub struct Cli {
    #[arg(long, help = "Input packet file path (.pcap or .pcapng). Required.")]
    pub input: PathBuf,

    #[arg(
        long,
        help = "Output file path. If omitted, defaults to current working directory with derived filename. For analyze, omitted output prints to console."
    )]
    pub output: Option<PathBuf>,

    #[arg(
        long,
        default_value_t = false,
        help = "Skip checksum recalculation/validation after packet modification (mainly for substitute_ip)."
    )]
    pub ignore_checksum: bool,

    #[arg(
        long,
        default_value_t = false,
        help = "Allow overwriting existing output file."
    )]
    pub overwrite: bool,

    #[command(subcommand)]
    pub command: Commands,
}

#[derive(Subcommand, Debug)]
pub enum Commands {
    #[command(
        name = "substitute_ip",
        about = "Replace packet src/dst IPs using one or more mapping rules",
        long_about = "Apply IP substitution rules to every packet.\n\nExample:\n  packet_handler --input in.pcap substitute_ip --map 10.0.0.1=1.1.1.1 --map 10.0.0.2=2.2.2.2\n\nNotes:\n- Repeat --map for multiple replacements\n- Mapping must be same IP family (IPv4->IPv4, IPv6->IPv6)"
    )]
    SubstituteIp {
        #[arg(
            long = "map",
            required = true,
            help = "IP mapping rule in FROM=TO form. Repeatable."
        )]
        maps: Vec<String>,
    },

    #[command(
        about = "Truncate each packet payload to N bytes",
        long_about = "Apply snaplen truncation to all packets.\n\nExample:\n  packet_handler --input in.pcap snaplen 128"
    )]
    Snaplen {
        #[arg(help = "Target snaplen in bytes (>0).")]
        n: usize,
    },

    #[command(
        about = "Filter packets with a BPF expression",
        long_about = "Extract packets matching BPF expression.\n\nExample:\n  packet_handler --input in.pcap filter \"tcp and port 443\"\n\nNotes:\n- Invalid BPF syntax causes immediate failure\n- For pcapng input, file is converted to pcap first, then filtered"
    )]
    Filter {
        #[arg(help = "BPF filter expression (quoted if contains spaces).")]
        bpf: String,
    },

    #[command(
        about = "Analyze conversations by protocol layer",
        long_about = "Print conversation summaries for selected layer.\n\nLayers:\n- ether, ip, tcp, icmp, udp, arp\n\nOutput:\n- Console when --output omitted\n- Text file when --output is provided"
    )]
    Analyze {
        #[arg(value_enum, help = "Conversation layer to analyze.")]
        layer: AnalyzeLayer,
    },
}

#[derive(Clone, Debug, ValueEnum)]
pub enum AnalyzeLayer {
    Ether,
    Ip,
    Tcp,
    Icmp,
    Udp,
    Arp,
}
