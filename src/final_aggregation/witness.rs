use crate::bellman::plonk::better_better_cs::cs::ConstraintSystem;
use crate::bellman::SynthesisError;
use crate::oracle_aggregation::OracleAggregationInputDataWitness;
use crate::{OracleAggregationInputData, UniformProof};
use cs_derive::*;
use derivative::Derivative;
use franklin_crypto::bellman::Engine;
use franklin_crypto::plonk::circuit::allocated_num::Num;
use franklin_crypto::plonk::circuit::boolean::Boolean;
use sync_vm::circuit_structures::traits::CircuitArithmeticRoundFunction;
use sync_vm::glue::optimizable_queue::commit_encodable_item;
use sync_vm::recursion::node_aggregation::{NodeAggregationOutputData, VK_ENCODING_LENGTH};
use sync_vm::recursion::recursion_tree::NUM_LIMBS;
use sync_vm::traits::*;
use sync_vm::traits::{CircuitFixedLengthEncodable, CircuitVariableLengthEncodable};
use sync_vm::vm::structural_eq::*;

#[derive(Derivative, serde::Serialize, serde::Deserialize)]
#[derivative(Clone, Debug)]
#[serde(bound = "")]
pub struct FinalAggregationCircuitInstanceWitness<E: Engine> {
    pub block_aggregation_result: BlockAggregationInputDataWitness<E>,
    pub oracle_aggregation_results: Vec<OracleAggregationInputDataWitness<E>>,

    pub oracle_vk_encoding_witness: Vec<E::Fr>,
    pub oracle_vk_commitment: E::Fr,
    pub block_vk_encoding_witness: Vec<E::Fr>,
    pub block_vk_commitment: E::Fr,
    #[derivative(Debug = "ignore")]
    pub block_proof_witness: UniformProof<E>,
    #[derivative(Debug = "ignore")]
    pub oracle_proof_witnesses: Vec<UniformProof<E>>,
}

impl<E: Engine> FinalAggregationCircuitInstanceWitness<E> {
    pub fn circuit_default(oracle_agg_num: usize) -> Self {
        assert!(oracle_agg_num <= 17);
        Self {
            block_aggregation_result:
                <BlockAggregationInputData<E> as CSWitnessable<E>>::placeholder_witness(),
            oracle_aggregation_results:
                vec![
                    <OracleAggregationInputData<E> as CSWitnessable<E>>::placeholder_witness();
                    oracle_agg_num
                ],

            oracle_vk_encoding_witness: vec![Default::default(); VK_ENCODING_LENGTH],
            oracle_vk_commitment: Default::default(),
            block_vk_encoding_witness: vec![Default::default(); VK_ENCODING_LENGTH],
            block_vk_commitment: Default::default(),

            block_proof_witness: UniformProof::empty(),
            oracle_proof_witnesses: vec![UniformProof::empty(); oracle_agg_num],
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
