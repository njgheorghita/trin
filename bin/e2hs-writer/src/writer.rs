use alloy::primitives::B256;
use e2store::{
    e2hs::{
        AccumulatorEntry, BlockIndex, BlockIndexEntry, BlockTuple, BodyEntry, HeaderWithProofEntry,
        ReceiptsEntry, E2HS,
    },
    e2store::types::{Entry, VersionEntry},
};
use futures::StreamExt;
use tracing::info;

use crate::reader::EpochReader;

pub struct EpochWriter {
    target_dir: String,
    epoch: u64,
}

impl EpochWriter {
    pub fn new(target_dir: String, epoch: u64) -> Self {
        Self { target_dir, epoch }
    }

    pub async fn write_epoch(&self, reader: EpochReader) -> anyhow::Result<()> {
        info!("Writing epoch {} to {}", self.epoch, self.target_dir);
        let mut block_tuples: Vec<BlockTuple> = vec![];
        let mut block_stream = Box::pin(reader.iter_blocks());

        while let Some(block) = block_stream.next().await {
            let block = block.unwrap();
            let header_with_proof = HeaderWithProofEntry {
                header_with_proof: block.header_with_proof,
            };
            let body = BodyEntry { body: block.body };
            let receipts = ReceiptsEntry {
                receipts: block.receipts,
            };
            let block_tuple = BlockTuple {
                header_with_proof,
                body,
                receipts,
            };
            block_tuples.push(block_tuple);
        }
        let version = VersionEntry {
            version: Entry::new(0x3265, vec![]),
        };
        let accumulator = AccumulatorEntry {
            accumulator: B256::default(),
        };
        let block_index = BlockIndex {
            starting_number: 0,
            indices: vec![],
            count: 0,
        };
        let block_index = BlockIndexEntry { block_index };
        let e2hs = E2HS {
            version,
            block_tuples,
            accumulator,
            block_index,
        };
        let raw_e2hs = e2hs.write().unwrap();
        let e2hs_path = format!("{}/{}.e2hs", self.target_dir, self.epoch);
        std::fs::write(e2hs_path.clone(), raw_e2hs).unwrap();
        info!("Wrote epoch {} to {}", self.epoch, e2hs_path);
        Ok(())
    }
}
