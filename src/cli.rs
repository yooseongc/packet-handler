use std::{net::IpAddr, path::PathBuf};

use clap::{Parser, Subcommand};

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
        #[arg(long)]
        from: IpAddr,
        #[arg(long)]
        to: IpAddr,
    },
    Snaplen {
        n: usize,
    },
}
