use std::{thread, time::Duration};

use ouroboros_consensus::{message::Message, network::Network};
use ouroboros_simulation::{network::random_topology, parameters::Parameters};
use tracing_subscriber::{fmt::format::FmtSpan, prelude::*, Registry};

pub fn main() {
    let subscriber = Registry::default();
    let json_log = tracing_subscriber::fmt::layer()
        .with_span_events(FmtSpan::CLOSE)
        .with_target(false)
        .with_level(false)
        .json();
    let subscriber = subscriber.with(json_log);

    tracing::subscriber::set_global_default(subscriber).expect("Unable to set global subscriber");

    let parameters = Parameters::default();
    let topology = random_topology(&mut rand::thread_rng(), &parameters);
    let network = Network::new(&topology, &parameters);
    let mut handle = network.start();
    for i in 0..1000 {
        thread::sleep(Duration::from_millis(10));
        handle.broadcast(Message::NextSlot(i));
    }

    handle.stop();

    for node_id in 1..10 {
        let chain = handle.get_preferred_chain(node_id);
        println!(
            "{{\"{}\": {}}}",
            node_id,
            serde_json::to_string(&chain).unwrap()
        );
    }
}
