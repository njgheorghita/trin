use ssz_derive::Encode;
use ssz;
use tiny_keccak::{Hasher, Keccak};

#[derive()]
pub struct AccountProof{
    pub content_type: u8,
    pub address: Address,
    pub state_root: [u8; 32],
}

//#[derive(Encode)]
pub struct AccountProofContainer{
    pub address: Address,
    pub state_root: [u8; 32],
}

#[derive(Clone, Copy)]
pub struct Address {
    bytes: [u8; 20],
}

impl ssz::Encode for Address {
    fn is_ssz_fixed_len() -> bool {
        true
    }

    //fn ssz_bytes_len(&self) -> usize {
        //20
    //}

    fn ssz_append(&self, buf: &mut Vec<u8>) {
        buf.append(&mut self.bytes.to_vec());
    }
}


impl AccountProof{
    pub fn get_content_key(&self) -> Vec<u8> {
        // 0x02 | Container(address: bytes20, state_root: bytes32)
        let mut content_key = [2u8].to_vec();
        let ssz_container = AccountProofContainer{
            address: self.address,
            state_root: self.state_root
        };
        //content_key.append(ssz_container.encode());
        content_key
        //self.state_root.to_vec()
    }

    // content_id = keccak(address)
    pub fn get_content_id(&self) -> [u8; 32] {
        let mut out = [0u8; 32];
        let mut hasher = Keccak::v256();
        //hasher.update(&self.address);
        hasher.finalize(&mut out);
        out
    }
}
