# Ouroboros

![Build Status](https://github.com/pragma-org/ouroboros/actions/workflows/validate.yml/badge.svg?branch=main)

Ouroboros is a family of proof-of-stake (PoS) consensus protocols used in blockchain technology. It was designed to be secure, scalable, and energy-efficient. Ouroboros is notable for being the first PoS protocol to be mathematically proven secure and for being the consensus algorithm behind the Cardano blockchain.  Key features of Ouroboros include:  

**Proof-of-Stake**: Unlike proof-of-work (PoW) systems, Ouroboros relies on stakeholders to validate transactions and create new blocks, which significantly reduces energy consumption.

**Security**: Ouroboros has been rigorously analyzed and proven secure under certain cryptographic assumptions.

**Scalability**: The protocol is designed to support a large number of transactions per second, making it suitable for large-scale applications.

**Incentives**: It includes mechanisms to incentivize honest behavior among participants, ensuring the network remains secure and efficient.
Ouroboros operates in epochs, which are divided into slots. In each slot, a slot leader is elected to add a block to the blockchain. The election process is based on the stake each participant holds, with higher stakes increasing the probability of being selected as a slot leader.

## Repository Layout

The ouroboros crate contains the generic traits related to any Ouroboros consensus protocol. The sub-libraries contain the specific implementations of Ouroboros, such as Ouroboros TPraos, Ouroboros Praos, and Ouroboros Genesis.
