use crate::bellman::plonk::better_better_cs::cs::{ConstraintSystem, VerificationKey};
use crate::bellman::SynthesisError;
use crate::oracle_aggregation::OracleAggregationInputDataWitness;
use crate::params::{CommonCryptoParams, COMMON_CRYPTO_PARAMS};
use crate::{
    OracleAggregationInputData, UniformCircuit,
    UniformProof,
};
use cs_derive::*;
use derivative::Derivative;
use franklin_crypto::bellman::Engine;
use franklin_crypto::plonk::circuit::allocated_num::Num;
use franklin_crypto::plonk::circuit::boolean::Boolean;
use sync_vm::circuit_structures::traits::CircuitArithmeticRoundFunction;
use sync_vm::glue::optimizable_queue::{commit_encodable_item, simulate_variable_length_hash};
use sync_vm::recursion::aggregation::VkInRns;
use sync_vm::recursion::node_aggregation::{NodeAggregationOutputData, VK_ENCODING_LENGTH};
use sync_vm::recursion::recursion_tree::NUM_LIMBS;
use sync_vm::testing::Bn256;
use sync_vm::traits::*;
use sync_vm::traits::{CircuitFixedLengthEncodable, CircuitVariableLengthEncodable};
use sync_vm::vm::structural_eq::*;

pub struct FinalAggregationCircuitInstanceWitness<'a, E: Engine> {
    pub block_aggregation_result: BlockAggregationInputDataWitness<E>,
    pub oracle_aggregation_results: Vec<OracleAggregationInputDataWitness<E>>,

    pub oracle_vk_encoding_witness: Vec<E::Fr>,
    pub oracle_vk_commitment: E::Fr,
    pub block_vk_encoding_witness: Vec<E::Fr>,
    pub block_vk_commitment: E::Fr,
    pub block_proof_witness: UniformProof<E>,
    pub oracle_proof_witnesses: Vec<UniformProof<E>>,
    pub(crate) params: &'a CommonCryptoParams<E>,
}

impl FinalAggregationCircuitInstanceWitness<'_, Bn256> {
    pub fn circuit_default(oracle_agg_num: usize) -> Self {
        assert!(oracle_agg_num <= 17);
        Self {
            block_aggregation_result:
                <BlockAggregationInputData<Bn256> as CSWitnessable<Bn256>>::placeholder_witness(),
            oracle_aggregation_results: vec![
                <OracleAggregationInputData<Bn256> as CSWitnessable<
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
            params: &COMMON_CRYPTO_PARAMS,
        }
    }

    pub fn generate(
        block_aggregation_result: BlockAggregationInputDataWitness<Bn256>,
        oracle_aggregation_results: Vec<OracleAggregationInputDataWitness<Bn256>>,
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

        Self {
            block_aggregation_result,
            oracle_aggregation_results,
            oracle_vk_encoding_witness,
            oracle_vk_commitment,
            block_vk_encoding_witness,
            block_vk_commitment,
            block_proof_witness,
            oracle_proof_witnesses,
            params: &COMMON_CRYPTO_PARAMS,
        }
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
pub struct BlockAggregationInputData<E: Engine> {
    pub vk_root: Num<E>,
    pub final_price_commitment: Num<E>, // consider previous_price_hash^2 + this_price_hash
    pub blocks_commitments: [Num<E>; BLOCK_AGG_NUM],
    pub aggregation_output_data: NodeAggregationOutputData<E>,
}

pub const BLOCK_AGG_NUM: usize = 36;
// On-chain information
#[derive(Derivative, CSWitnessable)]
#[derivative(Clone, Debug)]
pub struct FinalAggregationInputData<E: Engine> {
    pub vks_commitment: Num<E>,
    pub blocks_commitments: [Num<E>; BLOCK_AGG_NUM],
    pub oracle_data: OracleOnChainData<E>,
    pub aggregation_output_data: NodeAggregationOutputData<E>,
}

impl<E: Engine> FinalAggregationInputData<E> {
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
