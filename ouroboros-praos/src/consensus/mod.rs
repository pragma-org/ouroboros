use ouroboros::ledger::{issuer_vkey_to_pool_id, PoolId, PoolInfo};
use ouroboros::validator::Validator;
use pallas_crypto::hash::{Hash, Hasher};
use pallas_crypto::vrf::{
    VrfProof, VrfProofBytes, VrfProofHashBytes, VrfPublicKey, VrfPublicKeyBytes,
};
use pallas_math::math::{ExpOrdering, FixedDecimal, FixedPrecision};
use pallas_primitives::babbage;
use pallas_primitives::babbage::{derive_tagged_vrf_output, VrfDerivation};
use std::ops::Deref;
use std::sync::LazyLock;
use tracing::{error, span, trace, warn};

/// The certified natural max value represents 2^256 in praos consensus
static CERTIFIED_NATURAL_MAX: LazyLock<FixedDecimal> = LazyLock::new(|| {
    FixedDecimal::from_str(
        "1157920892373161954235709850086879078532699846656405640394575840079131296399360000000000000000000000000000000000",
        34,
    )
        .expect("Infallible")
});

/// Validator for a block using praos consensus.
pub struct BlockValidator<'b> {
    header: &'b babbage::Header,
    pool_info: &'b dyn PoolInfo,
    epoch_nonce: &'b Hash<32>,
    // c is the ln(1-active_slots_coeff). Usually ln(1-0.05)
    c: &'b FixedDecimal,
}

impl<'b> BlockValidator<'b> {
    pub fn new(
        header: &'b babbage::Header,
        pool_info: &'b dyn PoolInfo,
        epoch_nonce: &'b Hash<32>,
        c: &'b FixedDecimal,
    ) -> Self {
        Self {
            header,
            pool_info,
            epoch_nonce,
            c,
        }
    }

    fn validate_babbage_compatible(&self) -> bool {
        let span = span!(tracing::Level::TRACE, "validate_babbage_compatible");
        let _enter = span.enter();

        // Grab all the values we need to validate the block
        let issuer_vkey = &self.header.header_body.issuer_vkey;
        let pool_id: PoolId = issuer_vkey_to_pool_id(issuer_vkey);
        let vrf_vkey: VrfPublicKeyBytes = match (&self.header.header_body.vrf_vkey).try_into() {
            Ok(vrf_vkey) => vrf_vkey,
            Err(error) => {
                error!("Could not convert vrf_vkey: {}", error);
                return false;
            }
        };
        if !self.ledger_matches_block_vrf_key_hash(&pool_id, &vrf_vkey) {
            // Fail fast if the vrf key hash in the block does not match the ledger
            return false;
        }
        let sigma: FixedDecimal = match self.pool_info.sigma(&pool_id) {
            Ok(sigma) => {
                FixedDecimal::from(sigma.numerator) / FixedDecimal::from(sigma.denominator)
            }
            Err(error) => {
                warn!("{:?} - {:?}", error, pool_id);
                return false;
            }
        };
        let absolute_slot = self.header.header_body.slot;

        // Get the leader VRF output hash from the block vrf result
        let leader_vrf_output = &self.header.header_body.leader_vrf_output();

        let block_vrf_proof_hash: VrfProofHashBytes =
            match (&self.header.header_body.vrf_result.0).try_into() {
                Ok(block_vrf_proof_hash) => block_vrf_proof_hash,
                Err(error) => {
                    error!("Could not convert block vrf proof hash: {}", error);
                    return false;
                }
            };
        let block_vrf_proof: VrfProofBytes =
            match (&self.header.header_body.vrf_result.1).try_into() {
                Ok(block_vrf_proof) => block_vrf_proof,
                Err(error) => {
                    error!("Could not convert block vrf proof: {}", error);
                    return false;
                }
            };
        let kes_signature = self.header.body_signature.as_slice();

        trace!("pool_id: {}", pool_id);
        trace!("block vrf_vkey: {}", hex::encode(vrf_vkey));
        trace!("sigma: {}", sigma);
        trace!("absolute_slot: {}", absolute_slot);
        trace!("leader_vrf_output: {}", hex::encode(leader_vrf_output));
        trace!(
            "block_vrf_proof_hash: {}",
            hex::encode(block_vrf_proof_hash.as_slice())
        );
        trace!(
            "block_vrf_proof: {}",
            hex::encode(block_vrf_proof.as_slice())
        );
        trace!("kes_signature: {}", hex::encode(kes_signature));

        // Calculate the VRF input seed so we can verify the VRF output against it.
        let vrf_input_seed = self.mk_vrf_input(absolute_slot, self.epoch_nonce.as_ref());
        trace!("vrf_input_seed: {}", vrf_input_seed);

        // Verify the VRF proof
        let vrf_proof = VrfProof::from(&block_vrf_proof);
        let vrf_vkey = VrfPublicKey::from(&vrf_vkey);
        match vrf_proof.verify(&vrf_vkey, vrf_input_seed.as_ref()) {
            Ok(proof_hash) => {
                if proof_hash.as_slice() != block_vrf_proof_hash.as_slice() {
                    error!("VRF proof hash mismatch");
                    false
                } else {
                    // The proof was valid. Make sure that our leader_vrf_output matches what was in the block
                    trace!("certified_proof_hash: {}", hex::encode(proof_hash));
                    let calculated_leader_vrf_output =
                        derive_tagged_vrf_output(proof_hash.as_slice(), VrfDerivation::Leader);
                    if calculated_leader_vrf_output.as_slice() != leader_vrf_output.as_slice() {
                        error!(
                            "Leader VRF output hash mismatch. was: {}, expected: {}",
                            hex::encode(calculated_leader_vrf_output),
                            hex::encode(leader_vrf_output)
                        );
                        false
                    } else {
                        // The leader VRF output hash matches what was in the block
                        // Now we need to check if the pool had enough sigma stake to produce this block
                        if self.pool_meets_delegation_threshold(
                            &sigma,
                            absolute_slot,
                            leader_vrf_output.as_slice(),
                        ) {
                            // TODO: Validate the KES signature
                            true
                        } else {
                            false
                        }
                    }
                }
            }
            Err(error) => {
                error!("Could not verify block vrf: {}", error);
                false
            }
        }
    }

    /// Verify that the pool meets the delegation threshold
    fn pool_meets_delegation_threshold(
        &self,
        sigma: &FixedDecimal,
        absolute_slot: u64,
        leader_vrf_output: &[u8],
    ) -> bool {
        let certified_leader_vrf: FixedDecimal = leader_vrf_output.into();
        let denominator = CERTIFIED_NATURAL_MAX.deref() - &certified_leader_vrf;
        let recip_q = CERTIFIED_NATURAL_MAX.deref() / &denominator;
        let x = -(sigma * self.c);

        trace!("certified_leader_vrf: {}", certified_leader_vrf);
        trace!("denominator: {}", denominator);
        trace!("recip_q: {}", recip_q);
        trace!("c: {}", self.c);
        trace!("x: {}", x);

        let ordering = x.exp_cmp(1000, 3, &recip_q);
        match ordering.estimation {
            ExpOrdering::LT => {
                trace!(
                    "Slot: {} - IS Leader: {} < {}",
                    absolute_slot,
                    recip_q,
                    ordering.approx
                );
                true
            }
            _ => {
                trace!(
                    "Slot: {} - NOT Leader: {} >= {}",
                    absolute_slot,
                    recip_q,
                    ordering.approx
                );
                false
            }
        }
    }

    /// Validate that the VRF key hash in the block matches the VRF key hash in the ledger
    fn ledger_matches_block_vrf_key_hash(
        &self,
        pool_id: &PoolId,
        vrf_vkey: &VrfPublicKeyBytes,
    ) -> bool {
        let vrf_vkey_hash: Hash<32> = Hasher::<256>::hash(vrf_vkey);
        trace!("block vrf_vkey_hash: {}", hex::encode(vrf_vkey_hash));
        let ledger_vrf_vkey_hash = match self.pool_info.vrf_vkey_hash(pool_id) {
            Ok(ledger_vrf_vkey_hash) => ledger_vrf_vkey_hash,
            Err(error) => {
                warn!("{:?} - {:?}", error, pool_id);
                return false;
            }
        };
        if vrf_vkey_hash != ledger_vrf_vkey_hash {
            error!(
                "VRF vkey hash in block ({}) does not match registered ledger vrf vkey hash ({})",
                hex::encode(vrf_vkey_hash),
                hex::encode(ledger_vrf_vkey_hash)
            );
            return false;
        }
        true
    }

    fn mk_vrf_input(&self, absolute_slot: u64, eta0: &[u8]) -> Hash<32> {
        trace!("mk_vrf_input() absolute_slot {}", absolute_slot);
        let mut hasher = Hasher::<256>::new();
        hasher.input(&absolute_slot.to_be_bytes());
        hasher.input(eta0);
        hasher.finalize()
    }
}

impl Validator for BlockValidator<'_> {
    fn validate(&self) -> bool {
        self.validate_babbage_compatible()
    }
}

#[cfg(test)]
mod tests {
    use crate::consensus::BlockValidator;
    use ctor::ctor;
    use mockall::predicate::eq;
    use ouroboros::ledger::{MockPoolInfo, PoolId, PoolSigma};
    use ouroboros::validator::Validator;
    use pallas_crypto::hash::Hash;
    use pallas_math::math::{FixedDecimal, FixedPrecision};
    use pallas_traverse::MultiEraHeader;

    #[ctor]
    fn init() {
        // set rust log level to TRACE
        // std::env::set_var("RUST_LOG", "ouroboros-praos=trace");

        // initialize tracing crate
        tracing_subscriber::fmt::init();
    }

    #[test]
    fn test_validate_conway_block() {
        let test_block = include_bytes!("../../tests/data/mainnet_blockheader_10817298.cbor");
        let test_block_hex = hex::encode(test_block);
        insta::assert_snapshot!(test_block_hex);
        let test_vector = vec![
            (
                "00beef0a9be2f6d897ed24a613cf547bb20cd282a04edfc53d477114",
                "c0d1f9b040d2f6fd7fc8775d24753d6db4b697429f11404a6178a0a4a005867b",
                "c7937fc47fecbe687891b3decd71e904d1e129598aa3852481d295eea3ea3ada",
                25626202470912_u64,
                22586623335121436_u64,
                true,
            ),
            (
                "00beef0a9be2f6d897ed24a613cf547bb20cd282a04edfc53d477114",
                "c0d1f9b040d2f6fd7fc8775d24753d6db4b697429f11404a6178a0a4a005867b",
                "c7937fc47fecbe687891b3decd71e904d1e129598aa3852481d295eea3ea3ada",
                6026202470912_u64,
                22586623335121436_u64,
                false,
            ),
        ];
        insta::assert_yaml_snapshot!(test_vector);

        for (pool_id_str, vrf_vkey_hash_str, epoch_nonce_str, numerator, denominator, expected) in
            test_vector
        {
            let pool_id: PoolId = pool_id_str.parse().unwrap();
            let vrf_vkey_hash: Hash<32> = vrf_vkey_hash_str.parse().unwrap();
            let epoch_nonce: Hash<32> = epoch_nonce_str.parse().unwrap();

            let active_slots_coeff: FixedDecimal =
                FixedDecimal::from(5u64) / FixedDecimal::from(100u64);
            let c = (FixedDecimal::from(1u64) - active_slots_coeff).ln();
            let conway_block_tag: u8 = 6;
            let multi_era_header =
                MultiEraHeader::decode(conway_block_tag, None, test_block).unwrap();
            let babbage_header = multi_era_header.as_babbage().expect("Infallible");
            assert_eq!(babbage_header.header_body.slot, 134402628u64);

            let mut pool_info = MockPoolInfo::new();
            pool_info
                .expect_sigma()
                .with(eq(pool_id))
                .returning(move |_| {
                    Ok(PoolSigma {
                        numerator,
                        denominator,
                    })
                });
            pool_info
                .expect_vrf_vkey_hash()
                .with(eq(pool_id))
                .returning(move |_| Ok(vrf_vkey_hash));

            let block_validator = BlockValidator::new(babbage_header, &pool_info, &epoch_nonce, &c);
            assert_eq!(block_validator.validate(), expected);
        }
    }
}
