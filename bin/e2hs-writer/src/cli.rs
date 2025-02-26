use std::path::PathBuf;

use clap::Parser;
use portal_bridge::cli::DEFAULT_EPOCH_ACC_PATH;

#[derive(Parser, Debug, Clone)]
#[command(name = "E2HS Writer", about = "Generate E2HS files")]
pub struct WriterConfig {
    #[arg(long, help = "Target directory to write E2HS files")]
    pub target_dir: String,

    #[arg(long, help = "Epoch to generate E2HS files for")]
    pub epoch: u64,

    #[arg(
        long = "epoch-accumulator-path",
        help = "Path to epoch accumulator repo for bridge mode",
        default_value = DEFAULT_EPOCH_ACC_PATH
    )]
    pub epoch_acc_path: PathBuf,
}
