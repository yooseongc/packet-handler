use anyhow::Result;
use clap::Parser;

mod cli;
mod processor;
mod transform;

use cli::Cli;

fn main() -> Result<()> {
    let cli = Cli::parse();
    processor::run(&cli)
}
