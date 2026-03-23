pub mod core;
pub mod flat;
pub mod index;
pub mod session;
pub mod output;

use clap::{Parser, Subcommand};
use anyhow::Result;

#[derive(Parser)]
#[command(name = "trace-cli", about = "AI-first ARM64 trace analysis")]
struct Cli {
    /// Path to trace file
    file: String,

    #[command(subcommand)]
    command: Commands,
}

#[derive(Subcommand)]
enum Commands {
    /// Show trace lines in a range
    Lines {
        /// Line range, e.g. "100-200"
        range: String,
    },
    /// Backward taint analysis
    Taint {
        /// Target spec, e.g. "x0@last" or "x0@5000"
        spec: String,
        /// Only show tainted lines within this seq range, e.g. "3000-6000"
        #[arg(long)]
        range: Option<String>,
        /// Skip control flow dependencies (only follow data dependencies)
        #[arg(long)]
        data_only: bool,
        /// Filter out lines that only modify SP/FP registers
        #[arg(long)]
        ignore_sp: bool,
    },
    /// Show basic trace info (module, lines, entry, function count)
    Info,
    /// Search for a text pattern in the trace file
    Search {
        /// Case-insensitive substring to search for
        pattern: String,
        /// Only show matches within this seq range, e.g. "3000-6000"
        #[arg(long)]
        range: Option<String>,
    },
    /// Show all reads/writes to a memory address
    Xref {
        /// Memory address, e.g. "0x123e7024" or "123e7024"
        addr: String,
    },
    /// Reconstruct memory state at a given seq (hexdump)
    Memdump {
        /// Memory address, e.g. "0x123e7024" or "123e7024"
        addr: String,
        /// Number of bytes to dump (decimal, max 256)
        size: usize,
        /// Seq number to reconstruct at (default: last seq in trace)
        #[arg(long)]
        at: Option<u32>,
    },
}

fn main() -> Result<()> {
    let cli = Cli::parse();
    let session = session::Session::open(&cli.file)?;

    match cli.command {
        Commands::Lines { range } => {
            let parts: Vec<&str> = range.splitn(2, '-').collect();
            if parts.len() != 2 {
                anyhow::bail!("invalid range '{}': expected format 'START-END' (e.g. 0-20)", range);
            }
            let start: u32 = parts[0].parse()?;
            let end: u32 = parts[1].parse()?;
            output::print_lines(&session, start, end);
        }
        Commands::Taint { spec, range, data_only, ignore_sp } => {
            output::print_taint(&session, &spec, range.as_deref(), data_only, ignore_sp)?;
        }
        Commands::Info => {
            output::print_info(&session);
        }
        Commands::Search { pattern, range } => {
            output::print_search(&session, &pattern, range.as_deref());
        }
        Commands::Xref { addr } => {
            output::print_xref(&session, &addr)?;
        }
        Commands::Memdump { addr, size, at } => {
            output::print_memdump(&session, &addr, size, at)?;
        }
    }

    Ok(())
}
