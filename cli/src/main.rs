use clap::{Parser, ValueEnum};

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

fn main() -> std::io::Result<()> {
    let args = Args::parse();

    match args.command {
        CommandType::Activate => {
            let password = utils::get_password(args.passfile);
            service::activate_snapshot(&args.dev, &password);
            Ok(())
        }
        CommandType::Deactivate => {
            let password = utils::get_password(args.passfile);
            service::deactivate_snapshot(&args.dev, &password);
            Ok(())
        }
        CommandType::Restore => {
            let dir = args.session.as_ref().unwrap_or_else(|| {
                utils::log_error("Session path is required for restore");
                std::process::exit(1);
            });

            service::restore_snapshot(&args.dev, dir)
        }
    }
}

mod service;
mod utils;
