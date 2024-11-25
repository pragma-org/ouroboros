use crate::{
    block::{Block, PartyId},
    crypto::{Hash, MembershipProof, Signature},
};
use serde::{Deserialize, Serialize};

pub type RoundNumber = u64;

#[derive(Eq, Clone, PartialEq, Debug, Deserialize, Serialize, Hash)]
#[serde(rename_all = "camelCase")]
pub struct Vote {
    pub voting_round: RoundNumber,
    pub creator_id: PartyId,
    pub committee_membership_proof: MembershipProof,
    pub block_hash: Hash,
    pub signature: Signature,
}

pub type Chain = Vec<Block>;

pub fn empty_chain() -> Vec<Block> {
    return vec![];
}
