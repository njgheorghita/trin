use std::{
    fs,
    io::{Read, Write},
};

use alloy::{primitives::B256, rlp::Decodable};
use anyhow::ensure;
use ethportal_api::types::execution::{
    block_body::BlockBody, header_with_proof_new::HeaderWithProof, receipts::Receipts,
};
use ssz::{Decode, Encode};

use crate::e2store::{
    memory::E2StoreMemory,
    types::{Entry, VersionEntry},
};

// <config-name>-<era-number>-<era-count>-<short-historical-root>.era
//
// e2hs := Version | block-tuple* | other-entries* | Accumulator | BlockIndex
// block-tuple :=  CompressedHeader | CompressedBody | CompressedReceipts
// -----
// Version            = { type: 0x3269, data: nil }
// CompressedHWP      = { type: 0x03,   data: snappyFramed(ssz(header_with_proof)) }
// CompressedBody     = { type: 0x04,   data: snappyFramed(rlp(body)) }
// CompressedReceipts = { type: 0x05,   data: snappyFramed(rlp(receipts)) }
// Accumulator        = { type: 0x07,   data: hash_tree_root(List(block_hash, 8192)) }
// BlockIndex         = { type: 0x3266, data: block-index }

pub const BLOCK_TUPLE_COUNT: usize = 8192;
const E2HS_ENTRY_COUNT: usize = BLOCK_TUPLE_COUNT * 3 + 3;

pub struct E2HS {
    pub version: VersionEntry,
    pub block_tuples: Vec<BlockTuple>,
    pub accumulator: AccumulatorEntry,
    pub block_index: BlockIndexEntry,
}

impl E2HS {
    pub fn read_from_file(path: String) -> anyhow::Result<Self> {
        let buf = fs::read(path)?;
        Self::deserialize(&buf)
    }

    /// Function to iterate over block tuples in an e2hs file
    /// this is useful for processing large e2hs files without storing the entire
    /// deserialized e2hs object in memory.
    pub fn iter_tuples(raw_e2hs: Vec<u8>) -> impl Iterator<Item = BlockTuple> {
        let file = E2StoreMemory::deserialize(&raw_e2hs).expect("invalid e2hs file");
        let block_index =
            BlockIndexEntry::try_from(file.entries.last().expect("missing block index entry"))
                .expect("invalid block index entry")
                .block_index;
        (0..block_index.count).map(move |i| {
            let mut entries: [Entry; 3] = Default::default();
            for (j, entry) in entries.iter_mut().enumerate() {
                file.entries[i as usize * 3 + j + 1].clone_into(entry);
            }
            BlockTuple::try_from(&entries).expect("invalid block tuple")
        })
    }

    pub fn get_tuple_by_index(raw_e2hs: &[u8], index: u64) -> BlockTuple {
        let file = E2StoreMemory::deserialize(raw_e2hs).expect("invalid e2hs file");
        let mut entries: [Entry; 3] = Default::default();
        for (j, entry) in entries.iter_mut().enumerate() {
            file.entries[index as usize * 3 + j + 1].clone_into(entry);
        }
        BlockTuple::try_from(&entries).expect("invalid block tuple")
    }

    pub fn deserialize(buf: &[u8]) -> anyhow::Result<Self> {
        let file = E2StoreMemory::deserialize(buf)?;
        ensure!(
            file.entries.len() == E2HS_ENTRY_COUNT,
            "invalid e2hs file: incorrect entry count"
        );
        let version = VersionEntry::try_from(&file.entries[0])?;
        let block_index =
            BlockIndexEntry::try_from(file.entries.last().expect("missing block index entry"))?;
        let mut block_tuples = vec![];
        let block_tuple_count = block_index.block_index.count as usize;
        for count in 0..block_tuple_count {
            let mut entries: [Entry; 3] = Default::default();
            for (i, entry) in entries.iter_mut().enumerate() {
                *entry = file.entries[count * 3 + i + 1].clone();
            }
            let block_tuple = BlockTuple::try_from(&entries)?;
            block_tuples.push(block_tuple);
        }
        let accumulator_index = (block_tuple_count * 3) + 1;
        let accumulator = AccumulatorEntry::try_from(&file.entries[accumulator_index])?;
        Ok(Self {
            version,
            block_tuples,
            accumulator,
            block_index,
        })
    }

    pub fn write(&self) -> anyhow::Result<Vec<u8>> {
        let mut entries: Vec<Entry> = vec![];
        let version_entry: Entry = self.version.clone().into();
        entries.push(version_entry);
        for block_tuple in &self.block_tuples {
            let block_tuple_entries: [Entry; 3] = block_tuple.clone().try_into()?;
            entries.extend_from_slice(&block_tuple_entries);
        }
        let accumulator_entry: Entry = self.accumulator.clone().try_into()?;
        entries.push(accumulator_entry);
        let block_index_entry: Entry = self.block_index.clone().try_into()?;
        entries.push(block_index_entry);
        let file = E2StoreMemory { entries };
        ensure!(
            file.entries.len() == E2HS_ENTRY_COUNT,
            "invalid e2hs file: incorrect entry count"
        );
        let file_length = file.length();
        let mut buf = vec![0; file_length];
        file.write(&mut buf)?;
        Ok(buf)
    }

    pub fn epoch_number_from_block_number(block_number: u64) -> u64 {
        block_number / (BLOCK_TUPLE_COUNT as u64)
    }

    pub fn epoch_number(&self) -> u64 {
        Self::epoch_number_from_block_number(self.block_index.block_index.starting_number)
    }
}

#[derive(Clone, Eq, PartialEq, Debug)]
pub struct BlockTuple {
    pub header_with_proof: HeaderWithProofEntry,
    pub body: BodyEntry,
    pub receipts: ReceiptsEntry,
}

impl TryFrom<&[Entry; 3]> for BlockTuple {
    type Error = anyhow::Error;

    fn try_from(entries: &[Entry; 3]) -> anyhow::Result<Self> {
        let header_with_proof = HeaderWithProofEntry::try_from(&entries[0])?;
        let body = BodyEntry::try_from(&entries[1])?;
        let receipts = ReceiptsEntry::try_from(&entries[2])?;
        Ok(Self {
            header_with_proof,
            body,
            receipts,
        })
    }
}

impl TryInto<[Entry; 3]> for BlockTuple {
    type Error = anyhow::Error;

    fn try_into(self) -> anyhow::Result<[Entry; 3]> {
        Ok([
            self.header_with_proof.try_into()?,
            self.body.try_into()?,
            self.receipts.try_into()?,
        ])
    }
}

#[derive(Clone, Eq, PartialEq, Debug)]
pub struct HeaderWithProofEntry {
    pub header_with_proof: HeaderWithProof,
}

impl TryFrom<&Entry> for HeaderWithProofEntry {
    type Error = anyhow::Error;

    fn try_from(entry: &Entry) -> Result<Self, Self::Error> {
        ensure!(
            entry.header.type_ == 0x03,
            "invalid header entry: incorrect header type"
        );
        ensure!(
            entry.header.reserved == 0,
            "invalid header entry: incorrect header reserved bytes"
        );
        let mut decoder = snap::read::FrameDecoder::new(&entry.value[..]);
        let mut buf: Vec<u8> = vec![];
        decoder.read_to_end(&mut buf)?;
        let header_with_proof = HeaderWithProof::from_ssz_bytes(&buf).map_err(|e| {
            anyhow::anyhow!("failed to decode header with proof from ssz bytes: {:?}", e)
        })?;
        Ok(Self { header_with_proof })
    }
}

impl TryFrom<HeaderWithProofEntry> for Entry {
    type Error = anyhow::Error;

    fn try_from(value: HeaderWithProofEntry) -> Result<Self, Self::Error> {
        let ssz_encoded = value.header_with_proof.as_ssz_bytes();
        let buf: Vec<u8> = vec![];
        let mut encoder = snap::write::FrameEncoder::new(buf);
        let _ = encoder.write(&ssz_encoded)?;
        let encoded = encoder.into_inner()?;
        Ok(Entry::new(0x03, encoded))
    }
}
#[derive(Clone, Eq, PartialEq, Debug)]
pub struct BodyEntry {
    pub body: BlockBody,
}

impl TryFrom<&Entry> for BodyEntry {
    type Error = anyhow::Error;

    fn try_from(entry: &Entry) -> Result<Self, Self::Error> {
        ensure!(
            entry.header.type_ == 0x04,
            "invalid body entry: incorrect header type"
        );
        ensure!(
            entry.header.reserved == 0,
            "invalid body entry: incorrect header reserved bytes"
        );
        let mut decoder = snap::read::FrameDecoder::new(&entry.value[..]);
        let mut buf: Vec<u8> = vec![];
        decoder.read_to_end(&mut buf)?;
        let body = Decodable::decode(&mut buf.as_slice())?;
        Ok(Self { body })
    }
}

impl TryInto<Entry> for BodyEntry {
    type Error = anyhow::Error;

    fn try_into(self) -> Result<Entry, Self::Error> {
        let rlp_encoded = alloy::rlp::encode(self.body);
        let buf: Vec<u8> = vec![];
        let mut encoder = snap::write::FrameEncoder::new(buf);
        let _ = encoder.write(&rlp_encoded)?;
        let encoded = encoder.into_inner()?;
        Ok(Entry::new(0x04, encoded))
    }
}

#[derive(Clone, Eq, PartialEq, Debug)]
pub struct ReceiptsEntry {
    pub receipts: Receipts,
}

impl TryFrom<&Entry> for ReceiptsEntry {
    type Error = anyhow::Error;

    fn try_from(entry: &Entry) -> Result<Self, Self::Error> {
        ensure!(
            entry.header.type_ == 0x05,
            "invalid receipts entry: incorrect header type"
        );
        ensure!(
            entry.header.reserved == 0,
            "invalid receipts entry: incorrect header reserved bytes"
        );
        let mut decoder = snap::read::FrameDecoder::new(&entry.value[..]);
        let mut buf: Vec<u8> = vec![];
        decoder.read_to_end(&mut buf)?;
        let receipts: Receipts = Decodable::decode(&mut buf.as_slice())?;
        Ok(Self { receipts })
    }
}

impl TryInto<Entry> for ReceiptsEntry {
    type Error = anyhow::Error;

    fn try_into(self) -> Result<Entry, Self::Error> {
        let rlp_encoded = alloy::rlp::encode(&self.receipts);
        let buf: Vec<u8> = vec![];
        let mut encoder = snap::write::FrameEncoder::new(buf);
        let _ = encoder.write(&rlp_encoded)?;
        let encoded = encoder.into_inner()?;
        Ok(Entry::new(0x05, encoded))
    }
}

#[derive(Clone, Eq, PartialEq, Debug)]
pub struct AccumulatorEntry {
    pub accumulator: B256,
}

impl TryFrom<&Entry> for AccumulatorEntry {
    type Error = anyhow::Error;

    fn try_from(entry: &Entry) -> Result<Self, Self::Error> {
        ensure!(
            entry.header.type_ == 0x07,
            "invalid accumulator entry: incorrect header type"
        );
        ensure!(
            entry.header.length == 32,
            "invalid accumulator entry: incorrect header length"
        );
        ensure!(
            entry.header.reserved == 0,
            "invalid accumulator entry: incorrect header reserved bytes"
        );
        ensure!(
            entry.value.len() == 32,
            "invalid accumulator entry: incorrect value length"
        );
        let accumulator = B256::from_slice(&entry.value);
        Ok(Self { accumulator })
    }
}

impl TryInto<Entry> for AccumulatorEntry {
    type Error = anyhow::Error;

    fn try_into(self) -> Result<Entry, Self::Error> {
        let value = self.accumulator.as_slice().to_vec();
        Ok(Entry::new(0x07, value))
    }
}

//   block-index := starting-number | index | index | index ... | count

#[derive(Clone, Eq, PartialEq, Debug)]
pub struct BlockIndexEntry {
    pub block_index: BlockIndex,
}

impl TryFrom<&Entry> for BlockIndexEntry {
    type Error = anyhow::Error;

    fn try_from(entry: &Entry) -> Result<Self, Self::Error> {
        ensure!(
            entry.header.type_ == 0x3266,
            "invalid block index entry: incorrect header type"
        );
        ensure!(
            entry.header.length == 65552,
            "invalid block index entry: incorrect header length"
        );
        ensure!(
            entry.header.reserved == 0,
            "invalid block index entry: incorrect header reserved bytes"
        );
        ensure!(
            entry.value.len() == 65552,
            "invalid block index entry: incorrect value length"
        );
        Ok(Self {
            block_index: BlockIndex::try_from(entry.clone())?,
        })
    }
}

impl TryInto<Entry> for BlockIndexEntry {
    type Error = anyhow::Error;

    fn try_into(self) -> Result<Entry, Self::Error> {
        let mut buf: Vec<u64> = vec![];
        buf.push(self.block_index.starting_number);
        buf.extend_from_slice(&self.block_index.indices);
        buf.push(self.block_index.count);
        let encoded = buf
            .iter()
            .flat_map(|i| i.to_le_bytes().to_vec())
            .collect::<Vec<u8>>();
        Ok(Entry::new(0x3266, encoded))
    }
}

#[derive(Clone, Eq, PartialEq, Debug)]
pub struct BlockIndex {
    pub starting_number: u64,
    pub indices: Vec<u64>,
    pub count: u64,
}

impl TryFrom<Entry> for BlockIndex {
    type Error = anyhow::Error;

    fn try_from(entry: Entry) -> Result<Self, Self::Error> {
        let starting_number = u64::from_le_bytes(entry.value[0..8].try_into()?);
        let block_tuple_count = (entry.value.len() - 16) / 8;
        let mut indices = vec![0; block_tuple_count];
        for (i, index) in indices.iter_mut().enumerate() {
            *index = u64::from_le_bytes(entry.value[(i * 8 + 8)..(i * 8 + 16)].try_into()?);
        }
        let count = u64::from_le_bytes(
            entry.value[(block_tuple_count * 8 + 8)..(block_tuple_count * 8 + 16)].try_into()?,
        );
        Ok(Self {
            starting_number,
            indices,
            count,
        })
    }
}

/* #[cfg(test)] */
/* mod tests { */
/* use super::*; */

/* #[rstest::rstest] */
/* #[case::era1("../../test_assets/era1/mainnet-00000-5ec1ffb8.era1")] */
/* #[case::era1("../../test_assets/era1/mainnet-00001-a5364e9a.era1")] */
/* // epoch #10 contains txs */
/* #[case::era1("../../test_assets/era1/mainnet-00010-5f5d4516.era1")] */
/* // this is a test era1 file that has been amended for size purposes, */
/* // since era1 files that contain typed txs are quite large. */
/* // it was created by copying the `mainnet-01600-c6a9ee35.era1` file */
/* // - the first 10 block tuples are included, unchanged */
/* // - the following 8182 block tuples contain empty bodies and receipts */
/* #[case::era1("../../test_assets/era1/test-mainnet-01600-xxxxxxxx.era1")] */
/* fn test_era1(#[case] path: &str) { */
/* let era1 = Era1::read_from_file(path.to_string()).unwrap(); */
/* let actual = era1.write().unwrap(); */
/* let expected = fs::read(path).unwrap(); */
/* assert_eq!(expected, actual); */
/* let era1_raw_bytes = fs::read(path).unwrap(); */
/* let _block_tuples: Vec<BlockTuple> = Era1::iter_tuples(era1_raw_bytes).collect(); */
/* } */

/* #[rstest::rstest] */
/* #[case("../../test_assets/era1/mainnet-00000-5ec1ffb8.era1", 0)] */
/* #[case("../../test_assets/era1/mainnet-00001-a5364e9a.era1", 8192)] */
/* #[case("../../test_assets/era1/mainnet-00010-5f5d4516.era1", 81920)] */
/* fn test_era1_index(#[case] path: &str, #[case] index: u64) { */
/* let era1 = Era1::read_from_file(path.to_string()).unwrap(); */
/* assert_eq!(era1.block_index.block_index.starting_number, index); */
/* } */
/* } */
