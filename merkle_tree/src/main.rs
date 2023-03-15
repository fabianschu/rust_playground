extern crate tiny_keccak;

use hex::{decode};
use tiny_keccak::Hasher;

enum NodeSide {
    Right,
    Left
}
struct Node {
    hash_value: [u8; 32],
    node_side: NodeSide
}

impl PartialEq for NodeSide {
    fn eq(&self, other: &Self) -> bool {
        match (self, other) {
            (NodeSide::Left, NodeSide::Left) => true,
            (NodeSide::Right, NodeSide::Right) => true,
            _ => false,
        }
    }
}

fn decode_address(address: &str) -> Vec<u8> {
    let decoding_result = decode(&address[2..]);
    match decoding_result {
        Result::Ok(decoded_address) => return decoded_address,
        _ => panic!("Invalid address")
    }
}

fn hash_element(origin: Vec<u8>) -> [u8; 32] {
    let mut hasher = tiny_keccak::Sha3::v256();
    let mut hash_output:[u8; 32] = [0u8; 32];
    hasher.update(&origin);
    hasher.finalize(&mut hash_output);
    hash_output
}

fn concat_hashes(left: [u8; 32], right:[u8; 32]) -> Vec<u8> {
    let mut concatenated = Vec::<u8>::new();
    concatenated.extend(left);
    concatenated.extend(right);
    concatenated
}

fn get_next_node(left: [u8; 32], right:[u8; 32]) -> [u8; 32] {
    let concatenation = concat_hashes(left, right);
    let hash = hash_element(concatenation);
    hash
}

fn hash_layer(layer: &Vec<[u8; 32]>) -> Vec<[u8; 32]> {
    let mut next_layer = Vec::new();
    for i in (0..layer.len()).step_by(2) {
        let address_1: [u8; 32] = layer[i];
        let address_2: [u8; 32] = layer[i+1];
        next_layer.push(get_next_node(address_1,address_2));
    }
    next_layer
}

fn get_leaf_hashes(addresses: Vec<&str>) -> Vec<[u8; 32]> {
    let mut hashed_leafs: Vec<[u8; 32]> = Vec::new();
    for address in &addresses {
        hashed_leafs.push(get_leaf_hash(address));
    }
    // adds a zero if uneven amount of addresses
    if addresses.len() % 2 != 0 {
        hashed_leafs.push([0; 32]);
    }

    hashed_leafs
}

fn get_leaf_hash(address: &str)-> [u8;32] {
    let decoded = decode_address(address);
    let hash = hash_element(decoded);
    hash
}

fn generate_tree(leaf_hashes: Vec<[u8; 32]>) -> Vec<Vec<[u8; 32]>> {
    let mut tree: Vec<Vec<[u8; 32]>> = Vec::new();
    let leaf_hashes_copy = leaf_hashes.clone();
    tree.push(leaf_hashes_copy);

    loop {
        if let Some(inner_vec) = tree.last_mut() {
            if inner_vec.len() == 1 {
                return tree
            }
            if inner_vec.len() % 2 != 0 {
                inner_vec.push([0; 32]);
            }
            println!("{:?}", inner_vec.len());
            println!("{:?}", inner_vec);
            let next_layer = hash_layer(inner_vec);
            tree.push(next_layer);
        }
    }
}

fn generate_merkle_proof(leaf_index: usize, tree: Vec<Vec<[u8; 32]>>) -> Vec<Node> {

    let mut merkle_proof: Vec<Node> = Vec::new();
    let mut current_index = leaf_index;

    for layer in tree {
        if layer.len() == 1 { break; }
        if current_index % 2 == 0 {
            merkle_proof.push(Node {
                hash_value: layer[current_index + 1],
                node_side: NodeSide::Right
            })
        } else {
            merkle_proof.push(Node {
                hash_value: layer[current_index - 1],
                node_side: NodeSide::Left
            })
        }
        current_index = current_index / 2;
    }

    merkle_proof
}

fn validate_merkle_proof(merkle_proof: Vec<Node>, address: &str, root: [u8; 32]) -> bool {
    let mut current_hash  = get_leaf_hash(address);

    for node in merkle_proof {
        let mut concatenation: Vec<u8> = Vec::new();
        if node.node_side == NodeSide::Left {
            concatenation = concat_hashes(node.hash_value, current_hash);
        } else {
            concatenation = concat_hashes( current_hash, node.hash_value);
        }
        let hash = hash_element(concatenation);
        current_hash = hash;
    }

    current_hash == root
}

fn main() {
    let addresses = vec![
        "0x1234567890123456789012345678901234567890",
        "0x2345678901234567890123456789012345678901",
        "0x3456789012345678901234567890123456789012",
        "0x1234567890123456789012345678901234567890",
        "0x2345678901234567890123456789012345678901",
        "0x3456789012345678901234567890123456789012",
    ];

    let leaf_hashes = get_leaf_hashes(addresses);
    let tree = generate_tree(leaf_hashes);

    let tree_copy = tree.clone();
    let merkle_proof = generate_merkle_proof(1, tree);
    let is_included = validate_merkle_proof(merkle_proof, "0x2345678901234567890123456789012345678901", tree_copy.last().unwrap()[0]);
    println!("{:?}", is_included);
}