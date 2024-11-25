use crate::crypto::{Hash, LeadershipProof, Signature};
use serde::{Deserialize, Serialize};

pub type Slot = u64;

pub type PartyId = u64;

#[derive(Eq, Clone, PartialEq, Debug, Deserialize, Serialize, Hash)]
#[serde(tag = "tag", rename_all = "camelCase")]
pub struct Party {
    pub id: PartyId,
    #[serde(with = "hex::serde")]
    pub vkey: [u8; 8],
}

#[derive(Eq, Clone, PartialEq, Debug, Deserialize, Serialize, Hash)]
#[serde(tag = "tag", rename_all = "camelCase")]
pub struct Tx {}

#[derive(Eq, Clone, PartialEq, Debug, Deserialize, Serialize, Hash)]
#[serde(tag = "tag", rename_all = "camelCase")]
pub struct Block {
    pub slot_number: Slot,
    pub creator_id: PartyId,
    pub parent_block: Hash,
    pub certificate: Option<Certificate>,
    pub leadership_proof: LeadershipProof,
    pub signature: Signature,
    pub body_hash: Hash,
}

impl Block {
    pub fn genesis_hash() -> Hash {
        Hash {
            hash: [0, 0, 0, 0, 0, 0, 0, 0],
        }
    }
}

#[derive(Eq, Clone, PartialEq, Debug, Deserialize, Serialize, Hash)]
#[serde(tag = "tag", rename_all = "camelCase")]
pub struct BlockBody {
    pub block_hash: Hash,
    pub payload: Vec<Tx>,
}

#[derive(Eq, Clone, PartialEq, Debug, Deserialize, Serialize, Hash)]
#[serde(tag = "tag", rename_all = "camelCase")]
#[allow(non_snake_case)]
pub struct Certificate {
    pub voting_round_number: u64,
    pub blockRef: Hash,
}
