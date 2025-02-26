use anyhow::anyhow;
pub mod cli;
pub mod provider;
pub mod reader;
pub mod writer;
use clap::Parser;

use crate::reader::EpochReader;
use crate::writer::EpochWriter;

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    println!("e2hs writer");
    let config = cli::WriterConfig::parse();
    println!("{:?}", config);
    if config.epoch > 1895 {
        return Err(anyhow!("Epoch must be less than or equal to 1895"));
    }
    let epoch_reader = EpochReader::new(config.epoch, config.epoch_acc_path)
        .await
        .unwrap();
    let epoch_writer = EpochWriter::new(config.target_dir, config.epoch);
    epoch_writer.write_epoch(epoch_reader).await?;

    Ok(())
}
