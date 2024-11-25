use std::hash::Hasher;

use serde::{Deserialize, Serialize};

#[derive(Eq, Clone, PartialEq, Serialize, Deserialize, Debug)]
#[serde(transparent)]
pub struct Hash {
    #[serde(with = "hex::serde")]
    pub hash: [u8; 8],
}

impl std::hash::Hash for Hash {
    fn hash<H: Hasher>(&self, state: &mut H) {
        state.write(&self.hash);
    }
}

#[derive(Eq, Clone, PartialEq, Serialize, Deserialize, Debug, Hash)]
#[serde(transparent)]
pub struct LeadershipProof {
    #[serde(with = "hex::serde")]
    pub proof: [u8; 8],
}

#[derive(Eq, Clone, PartialEq, Serialize, Deserialize, Debug, Hash)]
#[serde(transparent)]
pub struct MembershipProof {
    #[serde(with = "hex::serde")]
    pub proof: [u8; 8],
}

#[derive(Eq, Clone, PartialEq, Serialize, Deserialize, Debug, Hash)]
#[serde(transparent)]
pub struct Signature {
    #[serde(with = "hex::serde")]
    pub signature: [u8; 8],
}
