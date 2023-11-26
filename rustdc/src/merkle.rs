use crate::config::FANOUT;
use crate::crypto::{hash_node, Hash, HashNode, NULL_HASH};

pub struct TreeNode {
    pub name: Hash,
    pub parent: Option<Hash>,
    pub signed: bool,
    pub children: HashNode,
}

pub struct RecordBlock {
    pub name: Hash,
    pub parent: Hash,
    pub sequence_number: u64,
}

// returns the hash of the root of the merkle tree
pub fn merkle_tree_root(hashes: &[Hash], additional_hash: &Hash) -> Hash {
    let mut current_layer = Vec::new();
    current_layer.extend(hashes);
    current_layer.push(*additional_hash);
    let mut bottom_layer = true;
    while bottom_layer || current_layer.len() > 1 {
        let len_next_layer = (current_layer.len() - 1) / FANOUT + 1;
        let mut next_layer = Vec::with_capacity(len_next_layer);
        for i in 0..(len_next_layer - 1) {
            let start_index = i * FANOUT;
            let children = current_layer[start_index..(start_index + FANOUT)]
                .try_into()
                .unwrap();
            next_layer.push(hash_node(&children));
        }
        let mut last_tree = [NULL_HASH; FANOUT];
        for i in 0..current_layer.len() - (len_next_layer - 1) * FANOUT {
            let start_index = (len_next_layer - 1) * FANOUT;
            last_tree[i] = current_layer[start_index + 1];
        }
        next_layer.push(hash_node(&last_tree));
        current_layer = next_layer;
        bottom_layer = false;
    }
    current_layer[0]
}

// returns record blocks to be stored, tree blocks to be stored
// and the parent of the additional hash
pub fn merkle_tree_storage(
    hashes: &[Hash],
    sequence_numbers: &[u64],
    additional_hash: &Hash,
) -> (Vec<RecordBlock>, Vec<TreeNode>, Hash) {
    let mut records = Vec::new();
    let mut treeblocks: Vec<TreeNode> = Vec::new();
    let mut additional_hash_parent = NULL_HASH;

    let mut current_layer = Vec::new();
    current_layer.extend(hashes);
    current_layer.push(*additional_hash);
    let mut bottom_layer = true;
    while bottom_layer || current_layer.len() > 1 {
        let len_next_layer = (current_layer.len() - 1) / FANOUT + 1;
        let mut next_layer = Vec::with_capacity(len_next_layer);
        for i in 0..(len_next_layer - 1) {
            let start_index = i * FANOUT;
            let children = current_layer[start_index..(start_index + FANOUT)]
                .try_into()
                .unwrap();
            let new_hash = hash_node(&children);
            next_layer.push(new_hash);
            treeblocks.push(TreeNode {
                name: new_hash,
                parent: None,
                signed: false,
                children,
            })
        }
        let mut last_tree = [NULL_HASH; FANOUT];
        for i in 0..current_layer.len() - (len_next_layer - 1) * FANOUT {
            let start_index = (len_next_layer - 1) * FANOUT;
            last_tree[i] = current_layer[start_index + 1];
        }
        let last_hash_in_next_layer = hash_node(&last_tree);
        next_layer.push(last_hash_in_next_layer);
        treeblocks.push(TreeNode {
            name: last_hash_in_next_layer,
            parent: None,
            signed: false,
            children: last_tree,
        });

        if bottom_layer {
            additional_hash_parent = last_hash_in_next_layer;
            for i in 0..(current_layer.len() - 1) {
                records.push(RecordBlock {
                    name: current_layer[i],
                    parent: next_layer[i / FANOUT],
                    sequence_number: sequence_numbers[i],
                });
            }
        } else {
            let start_idx = treeblocks.len() - next_layer.len() - current_layer.len();
            for i in 0..current_layer.len() {
                treeblocks[start_idx + i].parent = Some(next_layer[i / FANOUT]);
            }
        }
        current_layer = next_layer;
        bottom_layer = false;
    }

    treeblocks.last_mut().unwrap().signed = true;
    (records, treeblocks, additional_hash_parent)
}
