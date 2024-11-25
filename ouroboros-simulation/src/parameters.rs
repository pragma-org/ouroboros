use serde::{Deserialize, Serialize};

pub type Currency = u64;

pub type Slot = u64;

#[derive(Debug, Clone, Deserialize, PartialEq, Serialize)]
#[allow(non_snake_case)]
pub struct Parameters {
    pub randomSeed: u64,
    pub endSlot: Slot,
    pub peerCount: usize,
    pub downstreamCount: usize,
    pub totalStake: Option<Currency>,
    pub maximumStake: Currency,
    pub messageLatency: i64,
    pub messageBandwidth: i64,
}

impl Default for Parameters {
    fn default() -> Self {
        Parameters {
            randomSeed: 12345,
            peerCount: 10,
            downstreamCount: 3,
            totalStake: None,
            maximumStake: 1000,
            endSlot: 1000,
            messageLatency: 350000,
            messageBandwidth: 250,
        }
    }
}
