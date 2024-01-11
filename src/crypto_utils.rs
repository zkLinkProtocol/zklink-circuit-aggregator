use crate::params::{DefaultRescueParams, RescueTranscriptForRecursion};
use crate::{UniformCircuit, UniformProof};
use franklin_crypto::bellman::plonk::better_better_cs;
use franklin_crypto::bellman::plonk::better_better_cs::setup::VerificationKey;
use franklin_crypto::bellman::Engine;
use franklin_crypto::plonk::circuit::bigint::RnsParameters;
use sync_vm::circuit_structures::traits::CircuitArithmeticRoundFunction;
use sync_vm::glue::optimizable_queue::simulate_variable_length_hash;
use sync_vm::recursion::aggregation::VkInRns;
use sync_vm::recursion::node_aggregation::VK_ENCODING_LENGTH;
use sync_vm::traits::ArithmeticEncodable;

#[derive(Debug, Clone)]
pub struct PaddingCryptoComponent<E: Engine> {
    pub(crate) padding_vk_commitment: E::Fr,
    pub(crate) padding_vk_encoding: [E::Fr; VK_ENCODING_LENGTH],
    pub(crate) padding_public_input: Vec<E::Fr>,
    pub(crate) padding_proof: UniformProof<E>,
}

impl<E: Engine> PaddingCryptoComponent<E> {
    pub fn new<
        C: CircuitArithmeticRoundFunction<E, AWIDTH, SWIDTH>,
        const AWIDTH: usize,
        const SWIDTH: usize,
    >(
        padding_vk: VerificationKey<E, UniformCircuit<E>>,
        padding_proof: UniformProof<E>,
        commit_function: &C,
        rescue_params: &DefaultRescueParams<E>,
        rns_params: &RnsParameters<E, E::Fq>,
    ) -> PaddingCryptoComponent<E> {
        let transcript_params = (rescue_params, rns_params);
        assert!(
            better_better_cs::verifier::verify::<E, _, RescueTranscriptForRecursion<'_, E>>(
                &padding_vk,
                &padding_proof,
                Some(transcript_params),
            )
            .expect("must try to verify a proof"),
            "proof and VK must be valid"
        );

        let padding_vk_encoding: [_; VK_ENCODING_LENGTH] = VkInRns {
            vk: Some(padding_vk),
            rns_params,
        }
        .encode()
        .unwrap()
        .try_into()
        .unwrap();
        let padding_vk_commitment =
            simulate_variable_length_hash(&padding_vk_encoding, commit_function);

        Self {
            padding_vk_commitment,
            padding_vk_encoding,
            padding_public_input: padding_proof.inputs.clone(),
            padding_proof,
        }
    }
}
