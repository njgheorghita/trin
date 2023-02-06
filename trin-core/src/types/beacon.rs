use ethereum_types::H256;

//BeaconBlockBodyProof* = array[8, Digest]
pub struct BeaconBlockBodyProof {
    pub proof: [H256; 8],
}

//BeaconBlockHeaderProof* = array[3, Digest]
pub struct BeaconBlockHeaderProof {
    pub proof: [H256; 3],
}

//HistoricalRootsProof* = array[14, Digest]
pub struct HistoricalRootsProof {
    pub proof: [H256; 14],
}

//BeaconChainBlockProof* = object
//# Total size (8 + 1 + 3 + 1 + 14) * 32 bytes + 4 bytes = 868 bytes
//beaconBlockBodyProof: BeaconBlockBodyProof
//beaconBlockBodyRoot: Digest
//beaconBlockHeaderProof: BeaconBlockHeaderProof
//beaconBlockHeaderRoot: Digest
//historicalRootsProof: HistoricalRootsProof
//slot: Slot

pub struct BeaconChainBlockProof {
    pub beacon_block_body_proof: BeaconBlockBodyProof,
    pub beacon_block_body_root: H256,
    pub beacon_block_header_proof: BeaconBlockHeaderProof,
    pub beacon_block_header_root: H256,
    pub historical_roots_proof: HistoricalRootsProof,
    pub slot: u64,
}
