use bytes::Bytes;
use std::alloc::alloc::Global;
use ethereum_types::{Bloom, H160, H256, U256};
use super::header::Header;

/// A block body.
/// txs & uncles
///
///

pub struct BlockBody {
    pub tx_list: Vec<Transaction>,
    pub uncle_list: Vec<Header>
}


pub struct Transaction {
    pub hash: H256,
    pub nonce: U256,
    pub block_hash: Option<H256>,
    pub block_number: Option<u64>,
    pub transaction_index: Option<u64>,
    pub from: H160,
    pub to: Option<H160>,
    pub value: U256,
    pub gas_price: Option<U256>,
    pub gas: U256,
    pub input: Bytes,
    pub v: u64,
    pub r: U256,
    pub s: U256,
}

pub struct TransactionReceipts {
    pub receipt_list: Vec<TransactionReceipt>
}

pub struct TransactionReceipt {
    pub transaction_hash: H256,
    pub transaction_index: u64,
    pub block_hash: Option<H256>,
    pub block_number: Option<u64>,
    pub cumulative_gas_used: U256,
    pub gas_used: Option<U256>,
    pub contract_address: Option<H160>,
    //pub logs: Vec<Log, Global>,
    pub logs: Vec<(Log, Global)>,
    pub status: Option<u64>,
    pub root: Option<H256>,
    pub logs_bloom: Bloom,
    pub transaction_type: Option<u64>,
    pub effective_gas_price: Option<U256>,
}

pub struct Log {
    pub address: H160,
    //pub topics: Vec<H256, Global>,
    pub topics: Vec<(H256, Global)>,
    pub data: Bytes,
    pub block_hash: Option<H256>,
    pub block_number: Option<u64>,
    pub transaction_hash: Option<H256>,
    pub transaction_index: Option<u64>,
    pub log_index: Option<U256>,
    pub transaction_log_index: Option<U256>,
    pub log_type: Option<String>,
    pub removed: Option<bool>,
}
