use std::path::PathBuf;

use clap::{Parser, Subcommand, ValueEnum};

#[derive(Parser, Debug)]
#[command(name = "packet_handler")]
pub struct Cli {
    #[arg(long)]
    pub input: PathBuf,

    #[arg(long)]
    pub output: Option<PathBuf>,

    #[arg(long, default_value_t = false)]
    pub ignore_checksum: bool,

    #[arg(long, default_value_t = false)]
    pub overwrite: bool,

    #[command(subcommand)]
    pub command: Commands,
}

#[derive(Subcommand, Debug)]
pub enum Commands {
    #[command(name = "substitute_ip")]
    SubstituteIp {
        /// Multiple mappings: --map 1.1.1.1=2.2.2.2 --map 3.3.3.3=4.4.4.4
        #[arg(long = "map", required = true)]
        maps: Vec<String>,
    },
    Snaplen {
        n: usize,
    },
    Filter {
        /// BPF expression. Syntax error -> immediate failure.
        bpf: String,
    },
    Analyze {
        #[arg(value_enum)]
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
