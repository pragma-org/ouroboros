use crate::parameters::*;
use rand::seq::SliceRandom;
use rand::Rng;
use serde::{Deserialize, Deserializer, Serialize, Serializer};
use std::collections::HashMap;
use std::hash::Hash;

#[derive(Debug, Eq, Clone, Hash, PartialEq)]
#[allow(non_snake_case)]
pub struct NodeId {
    pub nodeId: String,
}

impl std::fmt::Display for NodeId {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> Result<(), std::fmt::Error> {
        write!(f, "{}", self.nodeId)
    }
}

impl<'a> Deserialize<'a> for NodeId {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'a>,
    {
        Ok(NodeId {
            nodeId: String::deserialize(deserializer)?,
        })
    }
}

impl Serialize for NodeId {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        serializer.serialize_str(&self.nodeId)
    }
}

#[allow(non_snake_case)]
pub fn MkNodeId(node_id: &str) -> NodeId {
    NodeId {
        nodeId: String::from(node_id),
    }
}

#[derive(Debug, PartialEq, Clone, Deserialize, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct NodeLink {
    latency: i64,
    reliability: f64,
}

#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct Topology {
    pub connections: HashMap<NodeId, HashMap<NodeId, NodeLink>>,
}

impl Topology {
    pub fn empty() -> Topology {
        Topology {
            connections: HashMap::new(),
        }
    }
}

fn map_singleton<K: Eq + Hash, V>(key: K, value: V) -> HashMap<K, V> {
    let mut map = HashMap::new();
    map.insert(key, value);
    map
}

// FIXME: Consider revising memory allocation.
pub fn connect_node(delay: i64, upstream: &NodeId, downstream: &NodeId, topology: &mut Topology) {
    let base_link = NodeLink {
        latency: delay,
        reliability: 1.0,
    };

    topology
        .connections
        .entry(upstream.clone())
        .and_modify(|v| {
            v.insert(downstream.clone(), base_link.clone());
        })
        .or_insert(map_singleton(downstream.clone(), base_link.clone()));
}

pub fn random_topology(rng: &mut impl Rng, parameters: &Parameters) -> Topology {
    let mut topology = Topology::empty();
    let node_ids: Vec<NodeId> = (1..=parameters.peerCount)
        .map(|i| NodeId {
            nodeId: format!("N{}", i),
        })
        .collect();
    fn random_connect(
        delay: i64,
        r: &mut impl Rng,
        upstream: &NodeId,
        downstreams: Vec<NodeId>,
        m: usize,
        t: &mut Topology,
    ) {
        let mut candidates = downstreams.clone();
        candidates.retain(|x| x != upstream);
        let chosen = candidates.choose_multiple(r, m);
        chosen.for_each(|downstream| connect_node(delay, upstream, downstream, t));
    }
    node_ids.iter().for_each(|upstream| {
        random_connect(
            parameters.messageLatency,
            rng,
            upstream,
            node_ids.clone(),
            parameters.downstreamCount,
            &mut topology,
        )
    });
    topology
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::{fs::File, io::BufReader, path::Path};

    #[derive(Debug, Deserialize, Serialize)]
    struct Golden<T> {
        samples: Vec<T>,
    }

    /*
    #[test]
    fn can_deserialize_topology_from_json() {
        let curfile = file!();
        // FIXME: having hardcoded relative path is not great for maintainability
        // and portability
        let golden_path = Path::new(curfile)
            .parent()
            .unwrap()
            .join("../../peras-iosim/golden/Topology.json");
        let golden_file = File::open(golden_path).expect("Unable to open file");
        let reader = BufReader::new(golden_file);
        let result: Result<Golden<Topology>, _> = serde_json::from_reader(reader);

        if let Err(err) = result {
            println!("{}", err);
            assert!(false);
        }
    }
    */
}
