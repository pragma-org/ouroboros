use std::{
    collections::HashMap,
    sync::{mpsc::Sender, Arc, Mutex},
    thread::{self, JoinHandle},
    time::Duration,
};

use netsim::{
    Bandwidth, HasBytesSize, NodePolicy, SimConfiguration, SimContext, SimId, SimSocket, TryRecv,
};
use ouroboros_simulation::{
    network::{NodeId, Topology},
    parameters::Parameters,
};
use rand::{rngs::StdRng, Rng, SeedableRng};

use chrono::Utc;

use crate::{
    chain::{empty_chain, Chain},
    event::UniqueId,
    message::Message,
    ouroboros_node::{
        InEnvelope, Node, NodeHandle, NodeParameters, OutEnvelope, ProtocolParameters,
    },
};

type Ctx = netsim::SimContext<Message>;

impl HasBytesSize for Message {
    fn bytes_size(&self) -> u64 {
        // FIXME this is lame...
        serde_json::to_vec(self).unwrap().len().try_into().unwrap()
    }
}

pub struct NodeInterface {
    /// The node's state
    node: Node,
    /// The socket for sending and receiving messages
    socket: Arc<Mutex<SimSocket<Message>>>,
    /// The socket's id
    socket_id: SimId,
}

#[allow(dead_code)]
pub struct Network {
    topology: Topology,
    parameters: Parameters,
    seed: StdRng,
    context: Ctx,
    nodes: HashMap<NodeId, NodeInterface>,
    chains: HashMap<NodeId, Chain>,
}

pub enum Control {
    BestChain(NodeId, Chain),
    Stopped(NodeId),
}

pub struct NetworkHandle {
    thread: Option<JoinHandle<()>>,
    network: Arc<Mutex<Network>>,
}

impl Network {
    pub fn new(topology: &Topology, parameters: &Parameters) -> Network {
        // configure the network simulation
        let configuration = SimConfiguration::default();

        // create the network context from which we can create "sockets"
        let mut context: Ctx = SimContext::with_config(configuration);

        // default protocol parameters
        let protocol = ProtocolParameters::default();

        let mut seed = StdRng::seed_from_u64(parameters.randomSeed);

        #[allow(non_snake_case)]
        let nodes: HashMap<NodeId, NodeInterface> = topology
            .connections
            .iter()
            .map(|(nodeId, _)| {
                let iface = make_node(
                    &nodeId.nodeId,
                    &mut context,
                    parameters,
                    &protocol,
                    &mut seed,
                );
                (nodeId.clone(), iface)
            })
            .collect();

        let chains = nodes
            .keys()
            .map(|node_id| (node_id.clone(), empty_chain()))
            .collect();

        Network {
            topology: topology.clone(),
            parameters: parameters.clone(),
            seed,
            context,
            nodes,
            chains,
        }
    }

    pub fn start(self) -> NetworkHandle {
        // creat communication channels with sub threads
        let (tx, rx) = std::sync::mpsc::channel();
        // start all nodes
        let _threads = self
            .nodes
            .iter()
            .map(|(node_id, iface)| {
                let mut node_handle = iface.node.start(self.parameters.maximumStake);
                let socket = Arc::clone(&iface.socket);
                let node_id_1 = node_id.clone();
                let tx_new = tx.clone();

                let downstreams = self
                    .topology
                    .connections
                    .get(&node_id_1)
                    .unwrap()
                    .iter()
                    .map(|(nid, _n)| self.nodes.get(nid).unwrap().socket_id)
                    .collect();
                // start dispatching thread for each node
                thread::spawn(move || {
                    receive_and_forward_loop(
                        node_id_1,
                        socket,
                        downstreams,
                        &mut node_handle,
                        &tx_new,
                    )
                })
            })
            .collect::<Vec<_>>();

        // FIXME shared network state is usually a recipe for deadlocks
        let network = Arc::new(Mutex::new(self));
        let network_shared = Arc::clone(&network);

        // start the control loop
        let thread = thread::spawn(move || loop {
            let recv = rx.recv();
            match recv {
                Ok(control) => {
                    let mut network = network_shared.lock().unwrap();
                    match control {
                        Control::BestChain(node_id, chain) => {
                            network.chains.insert(node_id, chain);
                        }
                        Control::Stopped(node_id) => {
                            network.nodes.remove(&node_id);
                            if network.nodes.is_empty() {
                                return;
                            }
                        }
                    }
                }
                Err(err) => {
                    println!("Error in control loop: {:?}", err);
                }
            }
        });

        NetworkHandle {
            thread: Some(thread),
            network,
        }
    }
}

impl NetworkHandle {
    pub fn stop(&mut self) {
        // stop all nodes
        self.broadcast(Message::Stop);
        // stop the control loop
        self.thread.take().unwrap().join().unwrap();
    }

    pub fn broadcast(&self, msg: Message) {
        // broadcast the message to all nodes in the network
        // we trick the node into thinking it's receiving a message from the network
        // by sending it to itself
        let network = self.network.lock().unwrap();
        for (_, iface) in network.nodes.iter() {
            let sock = iface.socket.lock().unwrap();
            sock.send_to(sock.id(), msg.clone()).expect("send failed");
        }
    }

    pub fn get_preferred_chain(&self, node_id: &str) -> Chain {
        let network = self.network.lock().unwrap();
        network
            .chains
            .get(&NodeId {
                nodeId: node_id.to_string(),
            })
            .unwrap()
            .clone()
    }
}

fn receive_and_forward_loop(
    node_id: NodeId,
    sim_socket: Arc<Mutex<SimSocket<Message>>>,
    downstreams: Vec<SimId>,
    node_handle: &mut NodeHandle,
    tx: &Sender<Control>,
) {
    let mut no_msg_count = 0;
    loop {
        thread::sleep(Duration::from_millis(no_msg_count));
        let mut socket = sim_socket.lock().unwrap();
        // handle messages that are sent to the node from the network
        match socket.try_recv() {
            TryRecv::Some((_, Message::Stop)) => {
                node_handle.send(InEnvelope::Stop);
            }
            TryRecv::Some((_, msg)) => {
                no_msg_count = 0;
                node_handle.send(InEnvelope::SendMessage {
                    origin: None,
                    in_id: UniqueId::new(&msg),
                    in_message: msg,
                    in_time: Utc::now(),
                    in_bytes: 0,
                });
            }
            TryRecv::NoMsg => {
                if no_msg_count < 10 {
                    no_msg_count += 1;
                };
            }
            TryRecv::Disconnected => {
                break;
            }
        }
        // pull messages from the node and send them to the network
        while let Some(envelope) = node_handle.try_receive() {
            match envelope {
                OutEnvelope::SendMessage {
                    out_message,
                    out_time: _,
                    source: _,
                    destination: _,
                    out_bytes: _,
                    out_id: _,
                } => {
                    downstreams.iter().for_each(|id| {
                        socket
                            .send_to(*id, out_message.clone())
                            .expect("send failed");
                    });
                }
                OutEnvelope::Idle {
                    timestamp: _,
                    source: _,
                    best_chain,
                } => {
                    tx.send(Control::BestChain(node_id.clone(), best_chain))
                        .expect("send failed");
                }
                OutEnvelope::Stopped(node_id) => {
                    tx.send(Control::Stopped(NodeId { nodeId: node_id }))
                        .expect("send failed");
                }
            }
        }
    }
}

fn make_node(
    node_id: &String,
    context: &mut Ctx,
    parameters: &Parameters,
    protocol: &ProtocolParameters,
    seed: &mut StdRng,
) -> NodeInterface {
    let socket = context.open().unwrap();
    let socket_id = socket.id();
    let socket_mutex = Arc::new(Mutex::new(socket));
    context
        .set_node_policy(
            socket_id,
            NodePolicy {
                bandwidth_down: Bandwidth::bits_per(u64::MAX, Duration::from_secs(1)),
                bandwidth_up: Bandwidth::bits_per(u64::MAX, Duration::from_secs(1)),
                location: None,
            },
        )
        .unwrap();

    let node_stake = seed.gen_range(0..parameters.maximumStake);

    let node_params = NodeParameters {
        node_stake,
        protocol_parameters: protocol.clone(),
    };

    let node = Node::new(node_id.to_string(), node_params);

    NodeInterface {
        node,
        socket: Arc::clone(&socket_mutex),
        socket_id,
    }
}
