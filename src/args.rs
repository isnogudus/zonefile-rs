#[derive(clap::ValueEnum, Clone)]
pub enum InputFormat {
    #[cfg(feature = "yaml")]
    Yaml,
    #[cfg(feature = "toml")]
    Toml,
}
