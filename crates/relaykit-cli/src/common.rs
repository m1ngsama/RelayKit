use anyhow::{anyhow, Result};
use serde::Serialize;
use tracing_subscriber::{fmt, EnvFilter};

pub fn init_tracing(verbosity: u8) -> Result<()> {
    let level = match verbosity {
        0 => "warn",
        1 => "info",
        _ => "debug",
    };

    let filter = EnvFilter::try_from_default_env().unwrap_or_else(|_| EnvFilter::new(level));
    fmt()
        .with_env_filter(filter)
        .try_init()
        .map_err(|err| anyhow!("failed to initialize tracing: {err}"))?;
    Ok(())
}

pub fn print_output<T>(json: bool, value: &T) -> Result<()>
where
    T: Serialize + std::fmt::Debug,
{
    if json {
        println!("{}", serde_json::to_string_pretty(value)?);
    } else {
        println!("{value:#?}");
    }

    Ok(())
}
