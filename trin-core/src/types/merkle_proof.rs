use crate::types::safe_arith::ArithError;
use eth2_hashing::{hash, hash32_concat, ZERO_HASHES};
use ethereum_types::H256;
use lazy_static::lazy_static;

const MAX_TREE_DEPTH: usize = 32;
const EMPTY_SLICE: &[H256] = &[];

lazy_static! {
    /// Zero nodes to act as "synthetic" left and right subtrees of other zero nodes.
    static ref ZERO_NODES: Vec<MerkleTree> = {
        (0..=MAX_TREE_DEPTH).map(MerkleTree::Zero).collect()
    };
}

/// Right-sparse Merkle tree.
///
/// Efficiently represents a Merkle tree of fixed depth where only the first N
/// indices are populated by non-zero leaves (perfect for the deposit contract tree).
#[derive(Debug, PartialEq)]
pub enum MerkleTree {
    /// Finalized Node
    Finalized(H256),
    /// Leaf node with the hash of its content.
    Leaf(H256),
    /// Internal node with hash, left subtree and right subtree.
    Node(H256, Box<Self>, Box<Self>),
    /// Zero subtree of a given depth.
    ///
    /// It represents a Merkle tree of 2^depth zero leaves.
    Zero(usize),
}

#[derive(Debug, PartialEq, Clone)]
pub enum MerkleTreeError {
    // Trying to push in a leaf
    LeafReached,
    // No more space in the MerkleTree
    MerkleTreeFull,
    // MerkleTree is invalid
    Invalid,
    // Incorrect Depth provided
    DepthTooSmall,
    // Overflow occurred
    ArithError,
    // Can't finalize a zero node
    ZeroNodeFinalized,
    // Can't push to finalized node
    FinalizedNodePushed,
    // Invalid Snapshot
    InvalidSnapshot(InvalidSnapshot),
    // Can't proof a finalized node
    ProofEncounteredFinalizedNode,
    // This should never happen
    PleaseNotifyTheDevs,
}

#[derive(Debug, PartialEq, Clone)]
pub enum InvalidSnapshot {
    // Branch hashes are empty but deposits are not
    EmptyBranchWithNonZeroDeposits(usize),
    // End of tree reached but deposits != 1
    EndOfTree,
}

impl MerkleTree {
    /// Create a new Merkle tree from a list of leaves and a fixed depth.
    pub fn create(leaves: &[H256], depth: usize) -> Self {
        use MerkleTree::*;

        if leaves.is_empty() {
            return Zero(depth);
        }

        match depth {
            0 => {
                debug_assert_eq!(leaves.len(), 1);
                Leaf(leaves[0])
            }
            _ => {
                // Split leaves into left and right subtrees
                let subtree_capacity = 2usize.pow(depth as u32 - 1);
                let (left_leaves, right_leaves) = if leaves.len() <= subtree_capacity {
                    (leaves, EMPTY_SLICE)
                } else {
                    leaves.split_at(subtree_capacity)
                };

                let left_subtree = MerkleTree::create(left_leaves, depth - 1);
                let right_subtree = MerkleTree::create(right_leaves, depth - 1);
                let hash = H256::from_slice(&hash32_concat(
                    left_subtree.hash().as_bytes(),
                    right_subtree.hash().as_bytes(),
                ));

                Node(hash, Box::new(left_subtree), Box::new(right_subtree))
            }
        }
    }

    /// Push an element in the MerkleTree.
    /// MerkleTree and depth must be correct, as the algorithm expects valid data.
    pub fn push_leaf(&mut self, elem: H256, depth: usize) -> Result<(), MerkleTreeError> {
        use MerkleTree::*;

        if depth == 0 {
            return Err(MerkleTreeError::DepthTooSmall);
        }

        match self {
            Leaf(_) => return Err(MerkleTreeError::LeafReached),
            Zero(_) => {
                *self = MerkleTree::create(&[elem], depth);
            }
            Node(ref mut hash, ref mut left, ref mut right) => {
                let left: &mut MerkleTree = &mut *left;
                let right: &mut MerkleTree = &mut *right;
                match (&*left, &*right) {
                    // Tree is full
                    (Leaf(_), Leaf(_)) | (Finalized(_), Leaf(_)) => {
                        return Err(MerkleTreeError::MerkleTreeFull)
                    }
                    // There is a right node so insert in right node
                    (Node(_, _, _), Node(_, _, _)) | (Finalized(_), Node(_, _, _)) => {
                        right.push_leaf(elem, depth - 1)?;
                    }
                    // Both branches are zero, insert in left one
                    (Zero(_), Zero(_)) => {
                        *left = MerkleTree::create(&[elem], depth - 1);
                    }
                    // Leaf on left branch and zero on right branch, insert on right side
                    (Leaf(_), Zero(_)) | (Finalized(_), Zero(_)) => {
                        *right = MerkleTree::create(&[elem], depth - 1);
                    }
                    // Try inserting on the left node -> if it fails because it is full, insert in right side.
                    (Node(_, _, _), Zero(_)) => {
                        match left.push_leaf(elem, depth - 1) {
                            Ok(_) => (),
                            // Left node is full, insert in right node
                            Err(MerkleTreeError::MerkleTreeFull) => {
                                *right = MerkleTree::create(&[elem], depth - 1);
                            }
                            Err(e) => return Err(e),
                        };
                    }
                    // All other possibilities are invalid MerkleTrees
                    (_, _) => return Err(MerkleTreeError::Invalid),
                };
                hash.assign_from_slice(&hash32_concat(
                    left.hash().as_bytes(),
                    right.hash().as_bytes(),
                ));
            }
            Finalized(_) => return Err(MerkleTreeError::FinalizedNodePushed),
        }

        Ok(())
    }

    /// Retrieve the root hash of this Merkle tree.
    pub fn hash(&self) -> H256 {
        match *self {
            MerkleTree::Finalized(h) => h,
            MerkleTree::Leaf(h) => h,
            MerkleTree::Node(h, _, _) => h,
            MerkleTree::Zero(depth) => H256::from_slice(&ZERO_HASHES[depth]),
        }
    }

    /// Get a reference to the left and right subtrees if they exist.
    pub fn left_and_right_branches(&self) -> Option<(&Self, &Self)> {
        match *self {
            MerkleTree::Finalized(_) | MerkleTree::Leaf(_) | MerkleTree::Zero(0) => None,
            MerkleTree::Node(_, ref l, ref r) => Some((l, r)),
            MerkleTree::Zero(depth) => Some((&ZERO_NODES[depth - 1], &ZERO_NODES[depth - 1])),
        }
    }

    /// Is this Merkle tree a leaf?
    pub fn is_leaf(&self) -> bool {
        matches!(self, MerkleTree::Leaf(_))
    }

    /// Finalize deposits up to deposit with count = deposits_to_finalize
    pub fn finalize_deposits(
        &mut self,
        deposits_to_finalize: usize,
        level: usize,
    ) -> Result<(), MerkleTreeError> {
        match self {
            MerkleTree::Finalized(_) => Ok(()),
            MerkleTree::Zero(_) => Err(MerkleTreeError::ZeroNodeFinalized),
            MerkleTree::Leaf(hash) => {
                if level != 0 {
                    // This shouldn't happen but this is a sanity check
                    return Err(MerkleTreeError::PleaseNotifyTheDevs);
                }
                *self = MerkleTree::Finalized(*hash);
                Ok(())
            }
            MerkleTree::Node(hash, left, right) => {
                if level == 0 {
                    // this shouldn't happen but we'll put it here for safety
                    return Err(MerkleTreeError::PleaseNotifyTheDevs);
                }
                let deposits = 0x1 << level;
                if deposits <= deposits_to_finalize {
                    *self = MerkleTree::Finalized(*hash);
                    return Ok(());
                }
                left.finalize_deposits(deposits_to_finalize, level - 1)?;
                if deposits_to_finalize > deposits / 2 {
                    let remaining = deposits_to_finalize - deposits / 2;
                    right.finalize_deposits(remaining, level - 1)?;
                }
                Ok(())
            }
        }
    }

    fn append_finalized_hashes(&self, result: &mut Vec<H256>) {
        match self {
            MerkleTree::Zero(_) | MerkleTree::Leaf(_) => {}
            MerkleTree::Finalized(h) => result.push(*h),
            MerkleTree::Node(_, left, right) => {
                left.append_finalized_hashes(result);
                right.append_finalized_hashes(result);
            }
        }
    }

    pub fn get_finalized_hashes(&self) -> Vec<H256> {
        let mut result = vec![];
        self.append_finalized_hashes(&mut result);
        result
    }

    pub fn from_finalized_snapshot(
        finalized_branch: &[H256],
        deposit_count: usize,
        level: usize,
    ) -> Result<Self, MerkleTreeError> {
        if finalized_branch.is_empty() {
            return if deposit_count == 0 {
                Ok(MerkleTree::Zero(level))
            } else {
                Err(InvalidSnapshot::EmptyBranchWithNonZeroDeposits(deposit_count).into())
            };
        }
        if deposit_count == (0x1 << level) {
            return Ok(MerkleTree::Finalized(
                *finalized_branch
                    .get(0)
                    .ok_or(MerkleTreeError::PleaseNotifyTheDevs)?,
            ));
        }
        if level == 0 {
            return Err(InvalidSnapshot::EndOfTree.into());
        }

        let (left, right) = match deposit_count.checked_sub(0x1 << (level - 1)) {
            // left tree is fully finalized
            Some(right_deposits) => {
                let (left_hash, right_branch) = finalized_branch
                    .split_first()
                    .ok_or(MerkleTreeError::PleaseNotifyTheDevs)?;
                (
                    MerkleTree::Finalized(*left_hash),
                    MerkleTree::from_finalized_snapshot(right_branch, right_deposits, level - 1)?,
                )
            }
            // left tree is not fully finalized -> right tree is zero
            None => (
                MerkleTree::from_finalized_snapshot(finalized_branch, deposit_count, level - 1)?,
                MerkleTree::Zero(level - 1),
            ),
        };

        let hash = H256::from_slice(&hash32_concat(
            left.hash().as_bytes(),
            right.hash().as_bytes(),
        ));
        Ok(MerkleTree::Node(hash, Box::new(left), Box::new(right)))
    }

    /// Return the leaf at `index` and a Merkle proof of its inclusion.
    ///
    /// The Merkle proof is in "bottom-up" order, starting with a leaf node
    /// and moving up the tree. Its length will be exactly equal to `depth`.
    pub fn generate_proof(
        &self,
        index: usize,
        depth: usize,
    ) -> Result<(H256, Vec<H256>), MerkleTreeError> {
        let mut proof = vec![];
        let mut current_node = self;
        let mut current_depth = depth;
        while current_depth > 0 {
            let ith_bit = (index >> (current_depth - 1)) & 0x01;
            if let &MerkleTree::Finalized(_) = current_node {
                return Err(MerkleTreeError::ProofEncounteredFinalizedNode);
            }
            // Note: unwrap is safe because leaves are only ever constructed at depth == 0.
            let (left, right) = current_node.left_and_right_branches().unwrap();

            // Go right, include the left branch in the proof.
            if ith_bit == 1 {
                proof.push(left.hash());
                current_node = right;
            } else {
                proof.push(right.hash());
                current_node = left;
            }
            current_depth -= 1;
        }

        debug_assert_eq!(proof.len(), depth);
        debug_assert!(current_node.is_leaf());

        // Put proof in bottom-up order.
        proof.reverse();

        Ok((current_node.hash(), proof))
    }

    /// useful for debugging
    pub fn print_node(&self, mut space: u32) {
        const SPACES: u32 = 10;
        space += SPACES;
        let (pair, text) = match self {
            MerkleTree::Node(hash, left, right) => (Some((left, right)), format!("Node({})", hash)),
            MerkleTree::Leaf(hash) => (None, format!("Leaf({})", hash)),
            MerkleTree::Zero(depth) => (
                None,
                format!("Z[{}]({})", depth, H256::from_slice(&ZERO_HASHES[*depth])),
            ),
            MerkleTree::Finalized(hash) => (None, format!("Finl({})", hash)),
        };
        if let Some((_, right)) = pair {
            right.print_node(space);
        }
        println!();
        for _i in SPACES..space {
            print!(" ");
        }
        println!("{}", text);
        if let Some((left, _)) = pair {
            left.print_node(space);
        }
    }
}

/// Verify a proof that `leaf` exists at `index` in a Merkle tree rooted at `root`.
///
/// The `branch` argument is the main component of the proof: it should be a list of internal
/// node hashes such that the root can be reconstructed (in bottom-up order).
pub fn verify_merkle_proof(
    leaf: H256,
    branch: &[H256],
    depth: usize,
    index: usize,
    root: H256,
) -> bool {
    if branch.len() == depth {
        merkle_root_from_branch(leaf, branch, depth, index) == root
    } else {
        false
    }
}

/// Compute a root hash from a leaf and a Merkle proof.
fn merkle_root_from_branch(leaf: H256, branch: &[H256], depth: usize, index: usize) -> H256 {
    assert_eq!(branch.len(), depth, "proof length should equal depth");

    let mut merkle_root = leaf.as_bytes().to_vec();

    for (i, leaf) in branch.iter().enumerate().take(depth) {
        let ith_bit = (index >> i) & 0x01;
        if ith_bit == 1 {
            merkle_root = hash32_concat(leaf.as_bytes(), &merkle_root)[..].to_vec();
        } else {
            let mut input = merkle_root;
            input.extend_from_slice(leaf.as_bytes());
            merkle_root = hash(&input);
        }
    }

    H256::from_slice(&merkle_root)
}

impl From<ArithError> for MerkleTreeError {
    fn from(_: ArithError) -> Self {
        MerkleTreeError::ArithError
    }
}

impl From<InvalidSnapshot> for MerkleTreeError {
    fn from(e: InvalidSnapshot) -> Self {
        MerkleTreeError::InvalidSnapshot(e)
    }
}
