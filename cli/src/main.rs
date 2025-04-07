use clap::{Parser, ValueEnum};
use std::fs;

/// CLI tool to control the snapshot service via FFI.
#[derive(Parser, Debug)]
#[command(author, version, about, long_about = None)]
struct Args {
    /// Command
    #[arg(value_enum)]
    command: CommandType,

    /// Device name. For block devices, use the format "/dev/sdX". For loop devices, specify the pathname associated to the file managed as device-file.
    #[arg(long)]
    dev: String,

    /// File path containing the snapshot service password.
    #[arg(long)]
    passfile: String,
}

#[derive(Copy, Clone, PartialEq, Eq, PartialOrd, Ord, Debug, ValueEnum)]
enum CommandType {
    Activate,
    Deactivate,
}

fn main() {
    // Parse command-line arguments.
    let args = Args::parse();

    // Read the password from the specified file.
    let password = fs::read_to_string(&args.passfile).unwrap_or_else(|e| {
        eprintln!("Error reading password file {}: {}", args.passfile, e);
        std::process::exit(1);
    });
    // Remove any trailing newline
    let password = password.trim();

    // Check if the user wants to activate or deactivate the snapshot service.
    match args.command {
        CommandType::Activate => {
            if let Err(e) = snapshot::activate_snapshot(&args.dev, password) {
                eprintln!("Error activating snapshot: {:?}", e);
            } else {
                println!("Snapshot activated successfully.");
            }
        }
        CommandType::Deactivate => {
            if let Err(e) = snapshot::deactivate_snapshot(&args.dev, password) {
                eprintln!("Error deactivating snapshot: {:?}", e);
            } else {
                println!("Snapshot deactivated successfully.");
            }
        }
    };
}

mod snapshot;
