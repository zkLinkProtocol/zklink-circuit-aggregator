use crate::params::{DefaultRescueParams, RescueTranscriptForRecursion, COMMON_CRYPTO_PARAMS};
use crate::{UniformCircuit, UniformProof, UniformVerificationKey};
use advanced_circuit_component::circuit_structures::traits::CircuitArithmeticRoundFunction;
use advanced_circuit_component::franklin_crypto::bellman::bn256::Bn256;
use advanced_circuit_component::franklin_crypto::bellman::plonk::better_better_cs;
use advanced_circuit_component::franklin_crypto::bellman::plonk::better_better_cs::setup::VerificationKey;
use advanced_circuit_component::franklin_crypto::bellman::Engine;
use advanced_circuit_component::franklin_crypto::plonk::circuit::bigint::RnsParameters;
use advanced_circuit_component::glue::optimizable_queue::simulate_variable_length_hash;
use advanced_circuit_component::recursion::aggregation::VkInRns;
use advanced_circuit_component::recursion::node_aggregation::VK_ENCODING_LENGTH;
use advanced_circuit_component::traits::ArithmeticEncodable;

#[derive(Debug, Clone)]
pub struct PaddingCryptoComponent<E: Engine> {
    pub padding_vk_commitment: E::Fr,
    pub padding_vk_encoding: [E::Fr; VK_ENCODING_LENGTH],
    pub padding_public_input: Vec<E::Fr>,
    pub padding_proof: UniformProof<E>,
    pub padding_vk: UniformVerificationKey<E>,
}

impl<E: Engine> Default for PaddingCryptoComponent<E> {
    fn default() -> Self {
        Self {
            padding_vk_commitment: Default::default(),
            padding_vk_encoding: [Default::default(); VK_ENCODING_LENGTH],
            padding_public_input: vec![Default::default()],
            padding_proof: UniformProof::empty(),
            padding_vk: UniformVerificationKey::empty(),
        }
    }
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
            vk: Some(padding_vk.clone()),
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
            padding_vk,
        }
    }
}

#[derive(Debug, Clone)]
pub struct VkEncodeInfo<E: Engine> {
    pub vk_encoding_witness: [E::Fr; VK_ENCODING_LENGTH],
    pub vk_commitment: E::Fr,
}

impl VkEncodeInfo<Bn256> {
    pub fn new(vk: UniformVerificationKey<Bn256>) -> Self {
        let commit_function = COMMON_CRYPTO_PARAMS.poseidon_hash();
        let vk_encoding_witness: [_; VK_ENCODING_LENGTH] = VkInRns {
            vk: Some(vk),
            rns_params: &COMMON_CRYPTO_PARAMS.rns_params,
        }
        .encode()
        .unwrap()
        .try_into()
        .unwrap();
        let vk_commitment = simulate_variable_length_hash(&vk_encoding_witness, &commit_function);
        Self {
            vk_encoding_witness,
            vk_commitment,
        }
    }
}

impl<E: Engine> Default for VkEncodeInfo<E> {
    fn default() -> Self {
        Self {
            vk_encoding_witness: [Default::default(); VK_ENCODING_LENGTH],
            vk_commitment: Default::default(),
        }
    }
}
