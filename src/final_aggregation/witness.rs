use crate::oracle_aggregation::OracleAggregationOutputDataWitness;
use crate::params::{CommonCryptoParams, COMMON_CRYPTO_PARAMS};
use crate::{final_aggregation, OracleAggregationOutputData, PaddingCryptoComponent, UniformCircuit, UniformProof};
use cs_derive::*;
use derivative::Derivative;
use advanced_circuit_component::franklin_crypto::bellman::plonk::better_better_cs::cs::ConstraintSystem;
use advanced_circuit_component::franklin_crypto::bellman::plonk::better_better_cs::setup::VerificationKey;
use advanced_circuit_component::franklin_crypto::bellman::{Engine, SynthesisError};
use advanced_circuit_component::franklin_crypto::plonk::circuit::allocated_num::Num;
use advanced_circuit_component::franklin_crypto::plonk::circuit::boolean::Boolean;
use advanced_circuit_component::franklin_crypto::plonk::circuit::byte::{Byte, IntoBytes};
use advanced_circuit_component::franklin_crypto::plonk::circuit::hashes_with_tables::keccak::gadgets::Keccak256Gadget;
use advanced_circuit_component::circuit_structures::traits::CircuitArithmeticRoundFunction;
use advanced_circuit_component::glue::optimizable_queue::{commit_encodable_item, simulate_variable_length_hash};
use advanced_circuit_component::recursion::aggregation::VkInRns;
use advanced_circuit_component::recursion::node_aggregation::{NodeAggregationOutputData, VK_ENCODING_LENGTH};
use advanced_circuit_component::recursion::recursion_tree::NUM_LIMBS;
use advanced_circuit_component::scheduler::block_header::keccak_output_into_bytes;
use advanced_circuit_component::testing::{Bn256, create_test_artifacts};
use advanced_circuit_component::traits::*;
use advanced_circuit_component::traits::{CircuitFixedLengthEncodable, CircuitVariableLengthEncodable};
use advanced_circuit_component::vm::structural_eq::*;

pub struct FinalAggregationCircuit<'a, E: Engine> {
    pub block_aggregation_result: BlockAggregationOutputDataWitness<E>,
    pub oracle_aggregation_results: Vec<OracleAggregationOutputDataWitness<E>>,

    pub oracle_vk_encoding_witness: Vec<E::Fr>,
    pub oracle_vk_commitment: E::Fr,
    pub block_vk_encoding_witness: Vec<E::Fr>,
    pub block_vk_commitment: E::Fr,
    pub block_proof_witness: UniformProof<E>,
    pub oracle_proof_witnesses: Vec<UniformProof<E>>,

    pub output: Option<FinalAggregationOutputDataWitness<E>>,
    pub(crate) params: &'a CommonCryptoParams<E>,
}

impl FinalAggregationCircuit<'_, Bn256> {
    pub fn circuit_default(oracle_agg_num: usize) -> Self {
        assert!(oracle_agg_num <= 17);
        Self {
            block_aggregation_result:
                <BlockAggregationOutputData<Bn256> as CSWitnessable<Bn256>>::placeholder_witness(),
            oracle_aggregation_results: vec![
                <OracleAggregationOutputData<Bn256> as CSWitnessable<
                    Bn256,
                >>::placeholder_witness();
                oracle_agg_num
            ],

            oracle_vk_encoding_witness: vec![Default::default(); VK_ENCODING_LENGTH],
            oracle_vk_commitment: Default::default(),
            block_vk_encoding_witness: vec![Default::default(); VK_ENCODING_LENGTH],
            block_vk_commitment: Default::default(),

            block_proof_witness: UniformProof::empty(),
            oracle_proof_witnesses: vec![UniformProof::empty(); oracle_agg_num],
            output: None,
            params: &COMMON_CRYPTO_PARAMS,
        }
    }

    pub fn generate(
        block_aggregation_result: BlockAggregationOutputDataWitness<Bn256>,
        oracle_aggregation_results: Vec<OracleAggregationOutputDataWitness<Bn256>>,
        oracle_vk: VerificationKey<Bn256, UniformCircuit<Bn256>>,
        block_vk: VerificationKey<Bn256, UniformCircuit<Bn256>>,
        block_proof_witness: UniformProof<Bn256>,
        oracle_proof_witnesses: Vec<UniformProof<Bn256>>,
    ) -> Self {
        assert_eq!(
            oracle_aggregation_results.len(),
            oracle_proof_witnesses.len()
        );

        let commit_function = COMMON_CRYPTO_PARAMS.poseidon_hash();
        let oracle_vk_encoding_witness = VkInRns {
            vk: Some(oracle_vk),
            rns_params: &COMMON_CRYPTO_PARAMS.rns_params,
        }
        .encode()
        .unwrap();
        let oracle_vk_commitment =
            simulate_variable_length_hash(&oracle_vk_encoding_witness, &commit_function);

        let block_vk_encoding_witness = VkInRns {
            vk: Some(block_vk),
            rns_params: &COMMON_CRYPTO_PARAMS.rns_params,
        }
        .encode()
        .unwrap();
        let block_vk_commitment =
            simulate_variable_length_hash(&block_vk_encoding_witness, &commit_function);

        let mut witness = Self {
            block_aggregation_result,
            oracle_aggregation_results,
            oracle_vk_encoding_witness,
            oracle_vk_commitment,
            block_vk_encoding_witness,
            block_vk_commitment,
            block_proof_witness,
            oracle_proof_witnesses,
            output: None,
            params: &COMMON_CRYPTO_PARAMS,
        };

        let agg_params = witness.params.aggregation_params();
        let rns_params = witness.params.rns_params.clone();
        let commit_hash = witness.params.poseidon_hash();
        let transcript_params = &witness.params.rescue_params;
        let padding = PaddingCryptoComponent::new(
            VerificationKey::empty(),
            UniformProof::empty(),
            &commit_hash,
            transcript_params,
            &rns_params,
        );
        let params = (
            witness.oracle_proof_witnesses.len() + 1,
            rns_params,
            agg_params,
            padding,
            Default::default(),
            None,
        );
        let (mut cs, ..) = create_test_artifacts();
        let (_public_input, public_input_data) = final_aggregation(&mut cs, Some(&witness), &commit_hash, params)
            .expect("Failed to final aggregate");
        witness.output = public_input_data.create_witness();

        witness
    }
}

#[derive(
    Derivative,
    CSAllocatable,
    CSWitnessable,
    CSPackable,
    CSSelectable,
    CSEqual,
    CSEncodable,
    CSDecodable,
    CSVariableLengthEncodable,
)]
#[derivative(Clone, Debug)]
pub struct BlockAggregationOutputData<E: Engine> {
    pub vk_root: Num<E>,
    pub final_price_commitment: Num<E>, // consider previous_price_hash^2 + this_price_hash
    pub blocks_commitments: [Num<E>; BLOCK_AGG_NUM],
    pub aggregation_output_data: NodeAggregationOutputData<E>,
}

pub const BLOCK_AGG_NUM: usize = 36;
// On-chain information
#[derive(Derivative, CSWitnessable)]
#[derivative(Clone, Debug)]
pub struct FinalAggregationOutputData<E: Engine> {
    pub vks_commitment: Num<E>,
    pub blocks_commitments: [Num<E>; BLOCK_AGG_NUM],
    pub oracle_data: OracleOnChainData<E>,
    pub aggregation_output_data: NodeAggregationOutputData<E>,
}

impl<E: Engine> FinalAggregationOutputData<E> {
    pub fn encode<
        CS: ConstraintSystem<E>,
        R: CircuitArithmeticRoundFunction<E, A_WIDTH, S_WIDTH, StateElement = Num<E>>,
        const A_WIDTH: usize,
        const S_WIDTH: usize,
    >(
        &self,
        cs: &mut CS,
        commit_function: &R,
    ) -> Result<Vec<Num<E>>, SynthesisError> {
        let mut encodes = Vec::with_capacity(3 + NUM_LIMBS * 4);
        encodes.push(self.vks_commitment);
        encodes.push(commit_encodable_item(
            cs,
            &self.blocks_commitments,
            commit_function,
        )?);
        encodes.push(commit_encodable_item(
            cs,
            &self.oracle_data,
            commit_function,
        )?);
        encodes.extend(CircuitFixedLengthEncodable::encode(
            &self.aggregation_output_data,
            cs,
        )?);
        assert_eq!(encodes.len(), encodes.capacity());
        Ok(encodes)
    }

    pub fn encode_bytes<CS: ConstraintSystem<E>>(
        &self,
        cs: &mut CS,
        keccak_gadget: &Keccak256Gadget<E>,
    ) -> Result<Vec<Byte<E>>, SynthesisError> {
        let len = 1usize + self.blocks_commitments.len() + 1 + 4 * NUM_LIMBS;
        let mut encodes = Vec::with_capacity(len * 32);
        encodes.extend(self.vks_commitment.into_be_bytes(cs)?);

        for block_commitment  in self.blocks_commitments {
            encodes.extend(block_commitment.into_be_bytes(cs)?);
        }

        let mut oracle_bytes = Vec::with_capacity(4 * 32);
        oracle_bytes.extend(self.oracle_data.used_pyth_num.into_be_bytes(cs)?);
        oracle_bytes.extend(self.oracle_data.guardian_set_index.into_be_bytes(cs)?);
        oracle_bytes.extend(self.oracle_data.guardian_set_hash.into_be_bytes(cs)?);
        oracle_bytes.extend(self.oracle_data.earliest_publish_time.into_be_bytes(cs)?);
        let digest = keccak_gadget.digest_from_bytes(cs, &oracle_bytes)?;
        let input_keccak_hash = keccak_output_into_bytes(cs, digest)?;
        encodes.extend(input_keccak_hash);

        for coord_limb in [
            self.aggregation_output_data.pair_with_generator_x,
            self.aggregation_output_data.pair_with_generator_y,
            self.aggregation_output_data.pair_with_x_x,
            self.aggregation_output_data.pair_with_x_y,
        ].iter().flatten() {
            encodes.extend(coord_limb.into_be_bytes(cs)?);

        }
        assert_eq!(encodes.len(), encodes.capacity());
        Ok(encodes)
    }
}

#[derive(
    Derivative,
    CSAllocatable,
    CSWitnessable,
    CSPackable,
    CSSelectable,
    CSEqual,
    CSEncodable,
    CSDecodable,
    CSVariableLengthEncodable,
)]
#[derivative(Clone, Debug)]
pub struct VksCompositionData<E: Engine> {
    pub oracle_vks_hash: Num<E>,
    pub block_vks_commitment: Num<E>,
}

#[derive(
    Derivative,
    CSAllocatable,
    CSWitnessable,
    CSPackable,
    CSSelectable,
    CSEqual,
    CSEncodable,
    CSDecodable,
    CSVariableLengthEncodable,
)]
#[derivative(Clone, Debug)]
pub struct OracleOnChainData<E: Engine> {
    pub used_pyth_num: Num<E>,
    pub guardian_set_index: Num<E>,
    pub guardian_set_hash: Num<E>,
    pub earliest_publish_time: Num<E>,
}

// Temp: Only for block aggregation circuit
#[derive(
    Derivative,
    CSAllocatable,
    CSWitnessable,
    CSPackable,
    CSSelectable,
    CSEqual,
    CSEncodable,
    CSDecodable,
    CSVariableLengthEncodable,
)]
#[derivative(Clone, Debug)]
pub struct BlockInputData<E: Engine> {
    pub blocks_commitments: Num<E>,
    pub price_commitment: Num<E>,
}
