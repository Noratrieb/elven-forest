use clap::Parser;
use tracing::metadata::LevelFilter;
use tracing_subscriber::EnvFilter;

fn main() -> anyhow::Result<()> {
    let opts = elven_wald::Opts::parse();
    let (_opts, _input) = elven_wald::opts::parse(std::env::args().skip(1))?;

    tracing_subscriber::fmt()
        .with_env_filter(
            EnvFilter::builder()
                .with_default_directive(LevelFilter::DEBUG.into())
                .from_env_lossy(),
        )
        .init();

    elven_wald::run(opts)
}
