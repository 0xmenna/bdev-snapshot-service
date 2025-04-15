use clap::{Parser, ValueEnum};
use std::fs;

/// CLI tool to manage the snapshot service.
#[derive(Parser, Debug)]
#[command(author, version, about, long_about = None)]
struct Args {
    /// Command
    #[arg(value_enum)]
    command: CommandType,

    /// Device name. For block devices, simply provide its name (e.g. sda). For loop devices, specify the pathname associated to the file managed as device-file.
    #[arg(long)]
    dev: String,

    /// File path containing the snapshot service password (only for activation or deactivation).
    #[arg(long)]
    passfile: Option<String>,

    /// Path to the snapshot session directory (required only for restore)
    #[arg(long)]
    session: Option<String>,
}

#[derive(Copy, Clone, PartialEq, Eq, PartialOrd, Ord, Debug, ValueEnum)]
enum CommandType {
    Activate,
    Deactivate,
    Restore,
}

fn main() {
    let args = Args::parse();

    match args.command {
        CommandType::Activate => {
            let password = get_password(args.passfile);
            if let Err(e) = snapshot::activate_snapshot(&args.dev, &password) {
                eprintln!("Error activating snapshot: {:?}", e);
            } else {
                println!("Snapshot activated successfully.");
            }
        }
        CommandType::Deactivate => {
            let password = get_password(args.passfile);
            if let Err(e) = snapshot::deactivate_snapshot(&args.dev, &password) {
                eprintln!("Error deactivating snapshot: {:?}", e);
            } else {
                println!("Snapshot deactivated successfully.");
            }
        }
        CommandType::Restore => {
            let dir = args.session.as_ref().unwrap_or_else(|| {
                eprintln!("--session is required for restore");
                std::process::exit(1);
            });

            if let Err(e) = snapshot::restore_snapshot(&args.dev, dir) {
                eprintln!("Error restoring snapshot: {:?}", e);
            } else {
                println!("Snapshot restored successfully.");
            }
        }
    };
}

fn get_password(passfile: Option<String>) -> String {
    if let Some(passfile) = passfile {
        let password = fs::read_to_string(&passfile).unwrap_or_else(|e| {
            eprintln!("Error reading password file {}: {}", &passfile, e);
            std::process::exit(1);
        });
        let password = password.trim();
        password.to_string()
    } else {
        eprintln!("Provide the password file");
        std::process::exit(1);
    }
}

mod snapshot;
