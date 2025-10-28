use anyhow::Result;
use clap::Parser;
use std::fs;
use std::io::Read;
use std::path::Path;
use zonefile_rs::args::InputFormat;

#[cfg(feature = "nsd")]
use zonefile_rs::output::nsd::write_nsd;
#[cfg(feature = "unbound")]
use zonefile_rs::output::unbound::generate_unbound;
use zonefile_rs::parser::parse;
use zonefile_rs::serial::{calc_serial, load_serial, save_serial};

// Default input format based on available features
#[cfg(feature = "yaml")]
const DEFAULT_INPUT_FORMAT: &str = "yaml";

#[cfg(all(feature = "toml", not(feature = "yaml")))]
const DEFAULT_INPUT_FORMAT: &str = "toml";

// Default output format based on available features
#[cfg(feature = "unbound")]
const DEFAULT_OUTPUT_FORMAT: &str = "unbound";

#[cfg(all(feature = "nsd", not(feature = "unbound")))]
const DEFAULT_OUTPUT_FORMAT: &str = "nsd";

#[derive(Parser)]
#[command(name = "zonefile-rs")]
#[command(about = "Generate DNS zone files from TOML or YAML configuration")]
struct Cli {
    /// Input file (default: stdin)
    #[arg(short, long, value_name = "FILE")]
    input: Option<String>,

    /// Input format: yaml or toml
    #[arg(short = 'I', long, value_name = "FORMAT", default_value = DEFAULT_INPUT_FORMAT)]
    input_format: InputFormat,

    /// Output file or directory
    #[arg(short, long, value_name = "PATH")]
    output: Option<String>,

    /// Output format: unbound or nsd
    #[arg(short = 'O', long, value_name = "FORMAT", default_value = DEFAULT_OUTPUT_FORMAT)]
    output_format: OutputFormat,

    /// Serial number file
    #[arg(short, long, value_name = "FILE", default_value = ".serial")]
    serial: String,
}

#[derive(clap::ValueEnum, Clone)]
enum OutputFormat {
    #[cfg(feature = "unbound")]
    Unbound,
    #[cfg(feature = "nsd")]
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

    let (forward, reverse) = parse(content.as_str(), serial, cli.input_format)?;
    match cli.output_format {
        #[cfg(feature = "unbound")]
        OutputFormat::Unbound => {
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
        #[cfg(feature = "nsd")]
        OutputFormat::Nsd => {
            let output_dir = cli.output.unwrap_or("./nsd".to_string());
            write_nsd(Path::new(&output_dir), &forward, &reverse)?;
        }
    }
    save_serial(path, serial)
}
