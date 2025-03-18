use alloy::{
    primitives::Address,
    rlp::{RlpDecodable, RlpEncodable},
    rpc::types::Withdrawal as AlloyWithdrawal,
};
use serde::{Deserialize, Serialize};
use serde_this_or_that::as_u64;
use ssz_derive::{Decode, Encode};
use tree_hash_derive::TreeHash;

//use crate::consensus::execution_payload::Withdrawal as ConsensusWithdrawal;

#[derive(
    Clone,
    Debug,
    PartialEq,
    Eq,
    Serialize,
    Deserialize,
    RlpDecodable,
    RlpEncodable,
    TreeHash,
    Encode,
    Decode,
)]
#[serde(rename_all = "camelCase")]
pub struct Withdrawal {
    #[serde(deserialize_with = "as_u64")]
    pub index: u64,
    #[serde(deserialize_with = "as_u64")]
    pub validator_index: u64,
    pub address: Address,
    #[serde(deserialize_with = "as_u64")]
    pub amount: u64,
}

/* fn string_to_u64<'de, D>(deserializer: D) -> Result<u64, D::Error> */
/* where */
/* D: Deserializer<'de>, */
/* { */
/* let s: String = Deserialize::deserialize(deserializer)?; */
/* u64::from_str_radix(s.trim_start_matches("0x"), 16) */
/* .map_err(|_| serde::de::Error::custom("failed to parse hex string")) */
/* } */

/* impl From<&ConsensusWithdrawal> for Withdrawal { */
/* fn from(withdrawal: &ConsensusWithdrawal) -> Self { */
/* Self { */
/* index: withdrawal.index, */
/* validator_index: withdrawal.validator_index, */
/* address: withdrawal.address, */
/* amount: withdrawal.amount, */
/* } */
/* } */
/* } */

impl From<&Withdrawal> for AlloyWithdrawal {
    fn from(withdrawal: &Withdrawal) -> Self {
        Self {
            index: withdrawal.index,
            validator_index: withdrawal.validator_index,
            address: withdrawal.address,
            amount: withdrawal.amount,
        }
    }
}
