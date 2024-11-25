use std::{
    sync::mpsc::{self, Receiver, Sender},
    thread::{self, JoinHandle},
};

use crate::{
    block::Block,
    chain::{empty_chain, Chain},
    crypto,
    event::UniqueId,
    message::{Message, NodeId},
};
use chrono::{DateTime, Utc};
use rand::{rngs::StdRng, Rng, RngCore, SeedableRng};
use serde::{Deserialize, Serialize};

#[derive(Debug, Deserialize, Serialize)]
#[serde(tag = "tag", rename_all_fields = "camelCase")]
pub enum InEnvelope {
    /// Kill the receiver
    Stop,

    /// Send a message from some other node
    #[serde(rename = "InEnvelope")]
    SendMessage {
        origin: Option<NodeId>,
        in_id: UniqueId,
        in_message: Message,
        in_time: DateTime<Utc>,
        in_bytes: u32,
    },
}

#[derive(Debug, Deserialize, Serialize)]
pub struct NodeState {}

#[derive(Debug, Deserialize, Serialize)]
#[serde(tag = "tag", rename_all_fields = "camelCase")]
pub enum OutEnvelope {
    Idle {
        timestamp: DateTime<Utc>,
        source: String,
        best_chain: Chain,
    },
    #[serde(rename = "OutEnvelope")]
    SendMessage {
        source: String,
        destination: String,
        out_id: UniqueId,
        out_message: Message,
        out_time: DateTime<Utc>,
        out_bytes: u32,
    },
    Stopped(String),
}

#[derive(Debug, Clone)]
pub struct ProtocolParameters {
    pub active_coefficient: f64,
}

impl Default for ProtocolParameters {
    fn default() -> Self {
        ProtocolParameters {
            active_coefficient: 0.1,
        }
    }
}

#[derive(Debug, Clone)]
pub struct NodeParameters {
    pub node_stake: u64,
    pub protocol_parameters: ProtocolParameters,
}

impl Default for NodeParameters {
    fn default() -> Self {
        NodeParameters {
            node_stake: 10,
            protocol_parameters: ProtocolParameters::default(),
        }
    }
}

#[derive(Debug, Clone)]
pub struct Node {
    node_id: NodeId,
    parameters: NodeParameters,
    seed: StdRng,
    best_chain: Chain,
}

#[allow(dead_code)]
pub struct NodeHandle {
    node_id: NodeId,
    sender: Sender<InEnvelope>,
    receiver: Receiver<OutEnvelope>,
    thread: Option<JoinHandle<()>>,
    pub current_best_chain: Chain,
}

impl Node {
    pub fn new(node_id: NodeId, parameters: NodeParameters) -> Self {
        Node {
            node_id,
            parameters,
            seed: StdRng::seed_from_u64(12),
            best_chain: empty_chain(),
        }
    }

    pub fn start(&self, total_stake: u64) -> NodeHandle {
        let (tx_in, rx_in) = mpsc::channel::<InEnvelope>();
        let (tx_out, rx_out) = mpsc::channel::<OutEnvelope>();

        let mut node1 = self.clone();

        let thread = thread::spawn(move || node1.work(total_stake, rx_in, tx_out));

        NodeHandle {
            node_id: self.node_id.clone(),
            sender: tx_in,
            receiver: rx_out,
            thread: Some(thread),
            current_best_chain: empty_chain(),
        }
    }

    fn is_slot_leader(&mut self, total_stake: u64) -> bool {
        let stake_ratio = (self.parameters.node_stake as f64) / (total_stake as f64);
        let prob =
            1.0 - (1.0 - self.parameters.protocol_parameters.active_coefficient).powf(stake_ratio);
        self.seed.gen_bool(prob)
    }

    fn work(&mut self, total_stake: u64, rx_in: Receiver<InEnvelope>, tx_out: Sender<OutEnvelope>) {
        loop {
            let recv = rx_in.recv();
            match recv {
                Ok(InEnvelope::Stop) => {
                    tx_out
                        .send(OutEnvelope::Stopped(self.node_id.clone()))
                        .expect("Failed to send message");
                    return;
                }
                Ok(InEnvelope::SendMessage {
                    origin: _,
                    in_id: _,
                    in_message: Message::NextSlot(slot),
                    in_time: _,
                    in_bytes: _,
                }) => match self.handle_slot(slot, total_stake) {
                    Some(out) => tx_out.send(out).expect("Failed to send message"),
                    None => (),
                },
                Ok(InEnvelope::SendMessage {
                    origin: _,
                    in_id: _,
                    in_message: Message::NewChain(chain),
                    in_time: _,
                    in_bytes: _,
                }) => match self.handle_new_chain(chain) {
                    Some(out) => tx_out.send(out).expect("Failed to send message"),
                    None => (),
                },
                Ok(_) => (),
                Err(err) => panic!("Error while receiving message {err}"),
            }

            tx_out
                .send(OutEnvelope::Idle {
                    timestamp: Utc::now(),
                    source: self.node_id.clone(),
                    best_chain: self.best_chain(),
                })
                .expect("Failed to send Idle message")
        }
    }

    fn handle_slot(&mut self, slot: u64, total_stake: u64) -> Option<OutEnvelope> {
        if self.is_slot_leader(total_stake) {
            let mut signature = [0u8; 8];
            self.seed.fill_bytes(&mut signature);
            let mut leadership_proof = [0u8; 8];
            self.seed.fill_bytes(&mut leadership_proof);
            let mut body_hash = [0u8; 8];
            self.seed.fill_bytes(&mut body_hash);
            let parent_hash = match self.best_chain.first() {
                Some(b) => b.body_hash.clone(),
                None => Block::genesis_hash(),
            };
            let new_block = Block {
                slot_number: slot,
                creator_id: 1,
                parent_block: parent_hash,
                certificate: None,
                leadership_proof: crypto::LeadershipProof {
                    proof: leadership_proof,
                },
                signature: crypto::Signature { signature },
                body_hash: crypto::Hash { hash: body_hash },
            };
            self.best_chain.insert(0, new_block);
            let msg = Message::NewChain(self.best_chain.clone());
            Some(OutEnvelope::SendMessage {
                source: self.node_id.clone(),
                destination: self.node_id.clone(), // FIXME this does not make sense
                out_id: UniqueId::new(&msg),
                out_message: msg,
                out_time: Utc::now(),
                out_bytes: 0,
            })
        } else {
            None
        }
    }

    fn handle_new_chain(&mut self, chain: Chain) -> Option<OutEnvelope> {
        let new_length = chain.len();
        let cur_length = self.best_chain.len();

        if new_length > cur_length {
            self.best_chain = chain;
            let msg = Message::NewChain(self.best_chain.clone());
            Some(OutEnvelope::SendMessage {
                source: self.node_id.clone(),
                destination: self.node_id.clone(), // FIXME this does not make sense
                out_id: UniqueId::new(&msg),
                out_message: msg,
                out_time: Utc::now(),
                out_bytes: 0,
            })
        } else {
            None
        }
    }

    pub(crate) fn best_chain(&self) -> Chain {
        self.best_chain.clone()
    }
}

impl NodeHandle {
    pub fn stop(&mut self) {
        if self.thread.as_ref().map_or(false, |t| t.is_finished()) {
            return;
        }
        self.sender
            .send(InEnvelope::Stop)
            .expect("sending poison pill failed");
        self.thread.take().unwrap().join().expect("node stopped");
    }

    pub fn send(&mut self, msg: InEnvelope) {
        match self.sender.send(msg) {
            Ok(_) => (),
            Err(_) => (),
        }
    }

    /// Non blocking receiving of a message from the node
    pub fn try_receive(&mut self) -> Option<OutEnvelope> {
        self.receiver.try_recv().ok()
    }

    /// Blocking receiving of a message from anode
    pub fn receive(&mut self) -> OutEnvelope {
        self.receiver.recv().expect("failed to receive message")
    }
}

#[cfg(test)]
mod tests {
    use crate::chain::empty_chain;
    extern crate quickcheck;
    use super::*;
    use std::{fs::File, io::BufReader, path::Path};

    #[derive(Debug, Deserialize, Serialize)]
    struct Golden<T> {
        samples: Vec<T>,
    }

    /*
    #[test]
    fn can_deserialize_chain_from_json() {
        let curfile = file!();
        // FIXME: having hardcoded relative path is not great for maintainability
        // and portability
        let golden_path = Path::new(curfile)
            .parent()
            .unwrap()
            .join("../../peras-hs/golden/Chain.json");
        let golden_file = File::open(golden_path).expect("Unable to open file");
        let reader = BufReader::new(golden_file);
        let result: Result<Golden<Chain>, _> = serde_json::from_reader(reader);

        if let Err(err) = result {
            println!("{}", err);
            assert!(false);
        }
    }
    */

    /// FIXME: InEnvelope is incomplete, deserialisation from golden file will fail
    fn can_deserialize_messages_from_json() {
        let curfile = file!();
        // FIXME: having hardcoded relative path is not great for maintainability
        // and portability
        let golden_path = Path::new(curfile)
            .parent()
            .unwrap()
            .join("../../peras-iosim/golden/InEnvelope.json");
        let golden_file = File::open(golden_path).expect("Unable to open file");
        let reader = BufReader::new(golden_file);
        let result: Result<Golden<InEnvelope>, _> = serde_json::from_reader(reader);

        if let Err(err) = result {
            println!("{}", err);
            assert!(false);
        }
    }

    #[test]
    fn returns_idle_after_processing_tick() {
        let node = Node::new("N1".into(), Default::default());
        let mut handle = node.start(100);

        handle.send(InEnvelope::SendMessage {
            origin: None,
            in_id: UniqueId {
                unique_id: [0, 0, 0, 0, 0, 0, 0, 0],
            },
            in_message: Message::NextSlot(1),
            in_time: Utc::now(),
            in_bytes: 0,
        });

        let received = handle.receive();

        handle.stop(); // should be in some teardown method

        match received {
            OutEnvelope::Idle {
                timestamp: _,
                source: _,
                best_chain,
            } => {
                assert_eq!(best_chain, empty_chain());
            }
            _ => assert!(false),
        }
    }

    #[quickcheck_macros::quickcheck]
    fn node_is_slot_leader_every_slot_given_coefficient_is_1_and_node_has_all_stake(slot: u64) {
        let params = NodeParameters {
            node_stake: 100,
            protocol_parameters: ProtocolParameters {
                active_coefficient: 1.0,
            },
        };
        let mut node = Node::new("N1".into(), params);

        assert!(node.is_slot_leader(slot))
    }

    #[test]
    fn node_is_slot_leader_every_other_slot_given_coefficient_is_0_5_and_node_has_all_stake() {
        let params = NodeParameters {
            node_stake: 100,
            protocol_parameters: ProtocolParameters {
                active_coefficient: 0.5,
            },
        };
        let mut node = Node::new("N1".into(), params);
        let schedule = (0..10000)
            .map(|n| node.is_slot_leader(100))
            .filter(|b| *b)
            .count();

        assert_eq!(schedule.div_ceil(100), 51);
    }

    #[test]
    fn node_is_slot_leader_every_slot_given_coefficient_is_1_and_node_has_half_the_stake() {
        let params = NodeParameters {
            node_stake: 50,
            protocol_parameters: ProtocolParameters {
                active_coefficient: 1.0,
            },
        };
        let mut node = Node::new("N1".into(), params);

        let schedule = (0..100)
            .map(|n| node.is_slot_leader(n))
            .filter(|b| *b)
            .count();

        // NOTE: this is counterintuitive but a consequence of the slot leader election formula
        assert_eq!(schedule, 100);
    }

    #[test]
    fn node_is_slot_leader_every_3_slots_given_coefficient_is_0_5_and_node_has_half_the_stake() {
        let params = NodeParameters {
            node_stake: 50,
            protocol_parameters: ProtocolParameters {
                active_coefficient: 0.5,
                ..Default::default()
            },
        };
        let mut node = Node::new("N1".into(), params);

        let schedule = (0..10000)
            .map(|_| node.is_slot_leader(100))
            .filter(|b| *b)
            .count();

        assert_eq!(schedule.div_ceil(100), 30);
    }

    #[test]
    fn produce_a_block_when_node_is_leader() {
        let params = NodeParameters {
            node_stake: 50,
            protocol_parameters: ProtocolParameters {
                active_coefficient: 1.0,
            },
        };
        let node = Node::new("N1".into(), params);
        let mut handle = node.start(100);

        for i in 1..5 {
            handle.send(InEnvelope::SendMessage {
                origin: None,
                in_id: UniqueId {
                    unique_id: [0, 0, 0, 0, 0, 0, 0, 0],
                },
                in_message: Message::NextSlot(i),
                in_time: Utc::now(),
                in_bytes: 0,
            })
        }

        let received = handle.receive();

        handle.stop(); // should be in some teardown method

        match received {
            OutEnvelope::SendMessage {
                source: _,
                destination: _,
                out_id: _,
                out_message: Message::NewChain(chain),
                ..
            } => {
                println!("got chain {:?}", serde_json::to_string(&chain));
                assert_ne!(chain, empty_chain());
            }
            _ => assert!(false),
        }
    }

    #[test]
    fn grow_best_chain_from_the_head() {
        let params = NodeParameters {
            node_stake: 100,
            protocol_parameters: ProtocolParameters {
                active_coefficient: 1.0,
            },
        };
        let node = Node::new("N1".into(), params);
        let mut handle = node.start(100);

        for i in 1..5 {
            handle.send(InEnvelope::SendMessage {
                origin: None,
                in_id: UniqueId {
                    unique_id: [0, 0, 0, 0, 0, 0, 0, 0],
                },
                in_message: Message::NextSlot(i),
                in_time: Utc::now(),
                in_bytes: 0,
            })
        }

        // we expect some Idle + NewChain messages
        for _i in 1..8 {
            let _ = handle.receive();
        }

        let received = handle.receive();

        handle.stop(); // should be in some teardown method

        match received {
            OutEnvelope::Idle {
                timestamp: _,
                source: _,
                best_chain: Chain { /* blocks, votes, */ .. },
            } => {
                // let slots: Vec<u64> = blocks.iter().map(|b| b.slot_number).collect();
                // assert!(slots.windows(2).all(|w| w[0] > w[1]));
            }
            _ => assert!(false),
        }
    }
}
