use ethportal_api::types::execution::header::{
    AccumulatorProof, BlockHeaderProof, Header, HeaderWithProof, SszNone,
};
use serde_json::Value;
use trin_bridge::bridge::Bridge;
use trin_bridge::cli::BridgeMode;
use trin_bridge::full_header::FullHeader;
use trin_validation::accumulator::MasterAccumulator;

#[cfg(test)]
mod tests {
    use trin_validation::oracle::HeaderOracle;
    #[test]
    fn full_xxx() {
        let master_acc =
            MasterAccumulator::try_from_file("validation_assets/merge_macc.bin".into())?;
        let header_oracle = HeaderOracle::new(master_acc);
        let mode = BridgeMode::Test(0);
        let portal_clients = vec![];
        let epoch_acc_path = "validation_assets/epoch_acc.bin".into();
        let bridge = Bridge::new(mode, portal_clients, header_oracle, epoch_acc_path);
        let body: Value = serde_json::from_str(&body).unwrap();
        let full_header = FullHeader::try_from(body["result"].clone()).unwrap();
        let header: Header = serde_json::from_value(body["result"].clone()).unwrap();
        assert_eq!(full_header.txs.len(), 19);
        assert_eq!(full_header.tx_hashes.hashes.len(), 19);
        assert_eq!(full_header.uncles.len(), 1);
        assert_eq!(full_header.header, header);
    }
}
