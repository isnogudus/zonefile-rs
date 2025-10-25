use anyhow::Result;
use clap::Parser;
use std::fs;
use std::io::Read;
use std::path::Path;

use zonefile_rs::output::nsd::write_nsd;
use zonefile_rs::output::unbound::generate_unbound;
use zonefile_rs::parser::parse_toml;
use zonefile_rs::serial::{calc_serial, load_serial, save_serial};

#[derive(Parser)]
#[command(name = "zonefile-rs")]
#[command(about = "Generate DNS zone files from TOML configuration")]
struct Cli {
    /// Input TOML file (default: stdin)
    #[arg(short, long, value_name = "FILE")]
    input: Option<String>,

    /// Output file or directory
    #[arg(short, long, value_name = "PATH")]
    output: Option<String>,

    /// Serial number file
    #[arg(short, long, value_name = "FILE", default_value = ".serial")]
    serial: String,

    /// Output format
    #[arg(short, long, value_name = "FORMAT", default_value = "unbound")]
    format: Format,
}

#[derive(clap::ValueEnum, Clone)]
enum Format {
    Unbound,
    Nsd,
}

fn main() -> Result<()> {
    let cli = Cli::parse();

    let path = Path::new(&cli.serial);
    let old_serial = load_serial(path);
    let serial = calc_serial(old_serial);

    let content = match cli.input {
        Some(file) => fs::read_to_string(file)?,
        None => {
            let mut buffer = String::new();
            std::io::stdin().read_to_string(&mut buffer)?;
            buffer
        }
    };
    let (forward, reverse) = parse_toml(content.as_str(), serial)?;
    match cli.format {
        Format::Unbound => {
            let output = generate_unbound(&forward, &reverse);
            match cli.output {
                Some(path) => {
                    let path = Path::new(&path);
                    fs::write(path, output)?;
                }
                None => {
                    print!("{output}");
                }
            }
        }
        Format::Nsd => {
            let output_dir = cli.output.unwrap_or("./nsd".to_string());
            write_nsd(Path::new(&output_dir), &forward, &reverse)?;
        }
    }
    save_serial(path, serial)
}
