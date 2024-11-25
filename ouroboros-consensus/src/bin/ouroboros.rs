use std::{thread, time::Duration};

use ouroboros_consensus::{message::Message, network::Network};
use ouroboros_simulation::{network::random_topology, parameters::Parameters};

pub fn main() {
    let parameters = Parameters::default();
    let topology = random_topology(&mut rand::thread_rng(), &parameters);
    let network = Network::new(&topology, &parameters);
    let mut handle = network.start();
    for i in 0..1000 {
        thread::sleep(Duration::from_millis(10));
        handle.broadcast(Message::NextSlot(i));
    }

    handle.stop();

    for i in 1..10 {
        let node_id = format!("N{}", i);
        let chain = handle.get_preferred_chain(&node_id);
        println!("Chain for {}: {:?}", node_id, chain);
    }
}
