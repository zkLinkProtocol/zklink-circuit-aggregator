use crate::padding::{DefaultRescueParams, RescueTranscriptForRecursion};
use crate::{UniformCircuit, UniformProof};
use cs_derive::*;
use derivative::Derivative;
use franklin_crypto::bellman::plonk::better_better_cs;
use franklin_crypto::bellman::plonk::better_better_cs::cs::ConstraintSystem;
use franklin_crypto::bellman::plonk::better_better_cs::setup::VerificationKey;
use franklin_crypto::bellman::Engine;
use franklin_crypto::bellman::SynthesisError;
use franklin_crypto::plonk::circuit::allocated_num::Num;
use franklin_crypto::plonk::circuit::bigint::RnsParameters;
use franklin_crypto::plonk::circuit::boolean::Boolean;
use std::collections::BTreeMap;
use sync_vm::circuit_structures::traits::CircuitArithmeticRoundFunction;
use sync_vm::glue::optimizable_queue::simulate_variable_length_hash;
use sync_vm::recursion::aggregation::VkInRns;
use sync_vm::recursion::node_aggregation::{NodeAggregationOutputData, VK_ENCODING_LENGTH};
use sync_vm::traits::*;
use sync_vm::vm::structural_eq::*;

pub const ORACLE_CIRCUIT_TYPES_NUM: usize = 6;
pub const ALL_AGGREGATION_TYPES: [OracleAggregationType; ORACLE_CIRCUIT_TYPES_NUM] = [
    OracleAggregationType::AggregationNull,
    OracleAggregationType::Aggregation1,
    OracleAggregationType::Aggregation2,
    OracleAggregationType::Aggregation3,
    OracleAggregationType::Aggregation4,
    OracleAggregationType::Aggregation5,
];

#[derive(Derivative, serde::Serialize, serde::Deserialize)]
#[derivative(Clone, Debug)]
#[serde(bound = "")]
pub struct OracleAggregationCircuit<E: Engine> {
    pub(crate) oracle_inputs_data: Vec<OracleOutputDataWitness<E>>,
    pub(crate) aggregation_type_set: Vec<OracleAggregationType>,
    pub(crate) vks_commitments_set: Vec<E::Fr>,
    pub(crate) vk_encoding_witnesses: Vec<Vec<E::Fr>>,
    #[derivative(Debug = "ignore")]
    pub(crate) proof_witnesses: Vec<UniformProof<E>>,
}

impl<E: Engine> OracleAggregationCircuit<E> {
    pub fn circuit_default(agg_num: usize) -> Self {
        assert!(agg_num <= 35);
        Self {
            oracle_inputs_data: vec![
                <OracleOutputData<E> as CSWitnessable<E>>::placeholder_witness(
                );
                agg_num
            ],
            aggregation_type_set: vec![Default::default(); agg_num],
            proof_witnesses: vec![UniformProof::empty(); agg_num],
            vks_commitments_set: vec![Default::default(); ORACLE_CIRCUIT_TYPES_NUM],
            vk_encoding_witnesses: vec![
                vec![Default::default(); VK_ENCODING_LENGTH];
                ORACLE_CIRCUIT_TYPES_NUM
            ],
        }
    }

    pub fn generate<
        C: CircuitArithmeticRoundFunction<E, A_WIDTH, S_WIDTH>,
        const A_WIDTH: usize,
        const S_WIDTH: usize,
    >(
        oracle_inputs_data: Vec<OracleOutputDataWitness<E>>,
        aggregation_type_set: Vec<OracleAggregationType>,
        proof_witnesses: Vec<UniformProof<E>>,
        vks: BTreeMap<OracleAggregationType, VerificationKey<E, UniformCircuit<E>>>,
        commit_function: &C,
        rescue_params: &DefaultRescueParams<E>,
        rns_params: &RnsParameters<E, E::Fq>,
    ) -> Self {
        assert_eq!(oracle_inputs_data.len(), aggregation_type_set.len());
        assert_eq!(oracle_inputs_data.len(), proof_witnesses.len());
        for (aggregation_type, proof) in aggregation_type_set.iter().zip(proof_witnesses.iter()) {
            let vk = vks.get(aggregation_type).unwrap();
            let transcript_params = (rescue_params, rns_params);
            assert!(
                better_better_cs::verifier::verify::<E, _, RescueTranscriptForRecursion<'_, E>>(
                    vk,
                    proof,
                    Some(transcript_params),
                )
                .expect("must try to verify a proof"),
                "proof and VK must be valid"
            );
        }

        let mut vks_commitments_set = Vec::with_capacity(vks.len());
        let mut vk_encoding_witnesses = Vec::with_capacity(vks.len());
        for (_, vk) in vks {
            let vk_encoding = VkInRns {
                vk: Some(vk),
                rns_params,
            }
            .encode()
            .unwrap();
            let vk_commitment = simulate_variable_length_hash(&vk_encoding, commit_function);
            vk_encoding_witnesses.push(vk_encoding);
            vks_commitments_set.push(vk_commitment);
        }

        Self {
            oracle_inputs_data,
            aggregation_type_set,
            vks_commitments_set,
            vk_encoding_witnesses,
            proof_witnesses,
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
pub struct OracleAggregationInputData<E: Engine> {
    pub oracle_vks_hash: Num<E>,
    pub guardian_set_hash: Num<E>,
    pub final_price_commitment: Num<E>,
    pub earliest_publish_time: Num<E>,
    pub aggregation_output_data: NodeAggregationOutputData<E>,
}

impl<E: Engine> CircuitEmpty<E> for OracleAggregationInputData<E> {
    fn empty() -> Self {
        Self {
            oracle_vks_hash: Num::zero(),
            guardian_set_hash: Num::zero(),
            final_price_commitment: Num::zero(),
            earliest_publish_time: Num::zero(),
            aggregation_output_data: CircuitEmpty::empty(),
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
pub struct OracleOutputData<E: Engine> {
    pub guardian_set_hash: Num<E>,
    pub final_price_commitment: Num<E>,
    pub earliest_publish_time: Num<E>,
}

impl<E: Engine> CircuitEmpty<E> for OracleOutputData<E> {
    fn empty() -> Self {
        Self {
            guardian_set_hash: Num::zero(),
            final_price_commitment: Num::zero(),
            earliest_publish_time: Num::zero(),
        }
    }
}

#[derive(
    Debug, Clone, Copy, Ord, PartialOrd, Eq, PartialEq, serde::Serialize, serde::Deserialize,
)]
pub enum OracleAggregationType {
    AggregationNull = 0, // For padding
    Aggregation1 = 1,
    Aggregation2 = 2,
    Aggregation3 = 3,
    Aggregation4 = 4,
    Aggregation5 = 5,
}

impl From<usize> for OracleAggregationType {
    fn from(value: usize) -> Self {
        match value {
            0 => Self::AggregationNull,
            1 => Self::Aggregation1,
            2 => Self::Aggregation2,
            3 => Self::Aggregation3,
            4 => Self::Aggregation4,
            5 => Self::Aggregation5,
            _ => unreachable!(),
        }
    }
}

impl Default for OracleAggregationType {
    fn default() -> Self {
        Self::AggregationNull
    }
}
