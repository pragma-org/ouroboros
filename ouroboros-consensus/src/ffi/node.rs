use std::{
    cmp,
    ffi::{c_char, CStr},
    slice,
};

use crate::ouroboros_node::{Node, NodeHandle, NodeParameters};

/// Opaque representation of a Consensus node for foreign use
pub struct ConsensusNode {
    handle: Box<NodeHandle>,
}

/// Creates and starts a new Consensus node
///
#[no_mangle]
pub unsafe extern "C" fn start_node(
    node_id: *const c_char,
    node_stake: u64,
    total_stake: u64,
) -> Box<ConsensusNode> {
    let node_id = CStr::from_ptr(node_id).to_str().unwrap().into();
    let node: Node = Node::new(
        node_id,
        NodeParameters {
            node_stake,
            ..Default::default()
        },
    );
    let handle = node.start(total_stake);
    Box::new(ConsensusNode {
        handle: Box::new(handle),
    })
}

#[no_mangle]
pub unsafe extern "C" fn stop_node(node: &mut ConsensusNode) {
    node.handle.stop()
}

#[no_mangle]
pub unsafe extern "C" fn send_message(node: &mut ConsensusNode, buf: *const u8, len: usize) {
    // make a slice
    let bytes = slice::from_raw_parts(buf, len);
    // unmarshall message
    match serde_json::from_slice(bytes) {
        Ok(msg) => node.handle.send(msg),
        Err(err) => println!(
            "Failed to deserialise message: {}\nError: {}",
            std::str::from_utf8(bytes).unwrap(),
            err
        ),
    }
}

#[no_mangle]
pub unsafe extern "C" fn receive_message(
    node: &mut ConsensusNode,
    buf: *mut u8,
    len: usize,
) -> usize {
    let msg = node.handle.receive();
    let bytes = serde_json::to_vec(&msg).unwrap();
    let bytes_ptr = bytes.as_ptr();
    let count_copy = cmp::min(len, bytes.len());

    unsafe {
        std::ptr::copy(bytes_ptr, buf, count_copy);
        count_copy
    }
}
