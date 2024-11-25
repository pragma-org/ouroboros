use serde::{Deserialize, Serialize};

use crate::block::{Block, BlockBody, Slot};
use crate::chain::{Chain, Vote};
use crate::crypto::Hash;

pub type NodeId = String;

#[derive(Debug, Clone, Deserialize, Serialize, Hash)]
#[serde(tag = "tag", content = "contents")]
pub enum Message {
    // control messages
    Stop,
    NextSlot(Slot),
    // actual protocol messages
    NewChain(Chain),
    SomeVote(Vote),
    FetchVotes(Vec<Hash>),
    FollowChain(Hash),
    RollForward(Block),
    RollBack(Block),
    FetchBlocks(Vec<Hash>),
    SomeBlock(BlockBody),
}

#[derive(Debug, Clone, Deserialize, Serialize)]
#[serde(tag = "tag", content = "contents")]
pub enum OutMessage {
    FetchBlock(Block),
    SendMessage(Message),
}
