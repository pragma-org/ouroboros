/**
 * FFI for Rust version of Consensus node
 *
 *
 * Copyright 2024, Input Output HK Ltd
 * Licensed with: Apache-2.0
 */

#ifndef CONSENSUS_LIBC
#define CONSENSUS_LIBC

/* Generated with cbindgen:0.26.0 */

/* Warning, this file is autogenerated by cbindgen. Don't modify this manually. */

#include <stdarg.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdlib.h>

/**
 * Opaque representation of a Consensus node for foreign use
 */
typedef struct ConsensusNode ConsensusNode;

typedef struct NetworkHandle NetworkHandle;

/**
 * Broadcasts a message to all nodes in the network
 */
void broadcast(struct NetworkHandle *network,
               const uint8_t *buf,
               uintptr_t len);

/**
 * Return the current preferred chain for given node
 *
 * The JSON representation of the chain is written to the given buffer and
 * the number of bytes written is returned.
 *
 * If the buffer is too small, the function returns the required buffer size.
 */
uintptr_t get_preferred_chain(struct NetworkHandle *network,
                              uint64_t node_id,
                              uint8_t *buf,
                              uintptr_t len);

uintptr_t receive_message(struct ConsensusNode *node,
                          uint8_t *buf,
                          uintptr_t len);

void send_message(struct ConsensusNode *node,
                  const uint8_t *buf,
                  uintptr_t len);

/**
 * Creates and starts a new Consensus network
 *
 * Creates a new network with the given topology and parameters and starts it.
 * The seed is used to initialize the random number generator.
 */
struct NetworkHandle *start_network(const char *topology,
                                    const char *parameters);

/**
 * Creates and starts a new Consensus node
 *
 */
struct ConsensusNode *start_node(uint64_t node_id,
                                 uint64_t node_stake,
                                 uint64_t total_stake);

/**
 * Stops the given Consensus network
 */
void stop_network(struct NetworkHandle *network);

void stop_node(struct ConsensusNode *node);

#endif /* CONSENSUS_LIBC */
