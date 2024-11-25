use serde::{Deserialize, Serialize};
use std::hash::{Hash, Hasher};
use std::collections::hash_map::DefaultHasher;

/// Unique identifier for various entities in the network.
/// Currently used for identifying messages from their content.
#[derive(Eq, Clone, PartialEq, Serialize, Deserialize, Debug)]
#[serde(transparent, rename_all = "camelCase")]
pub struct UniqueId {
    #[serde(with = "hex::serde")]
    pub unique_id: [u8; 8],
}

impl UniqueId {
    pub fn new<H: Hash>(payload: H) -> UniqueId {
        let mut hasher = DefaultHasher::new();
        payload.hash(&mut hasher);
        UniqueId {
            unique_id: hasher.finish().to_be_bytes(),
        }
    }
}
