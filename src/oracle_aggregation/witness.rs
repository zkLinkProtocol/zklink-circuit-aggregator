use crate::params::{CommonCryptoParams, RescueTranscriptForRecursion, COMMON_CRYPTO_PARAMS};
use crate::{
    aggregate_oracle_proofs, PaddingCryptoComponent, UniformCircuit, UniformProof, VkEncodeInfo,
};
use advanced_circuit_component::franklin_crypto::bellman::bn256::Bn256;
use advanced_circuit_component::franklin_crypto::bellman::plonk::better_better_cs;
use advanced_circuit_component::franklin_crypto::bellman::plonk::better_better_cs::cs::ConstraintSystem;
use advanced_circuit_component::franklin_crypto::bellman::plonk::better_better_cs::setup::VerificationKey;
use advanced_circuit_component::franklin_crypto::bellman::Engine;
use advanced_circuit_component::franklin_crypto::bellman::SynthesisError;
use advanced_circuit_component::franklin_crypto::plonk::circuit::allocated_num::Num;
use advanced_circuit_component::franklin_crypto::plonk::circuit::boolean::Boolean;
use advanced_circuit_component::recursion::node_aggregation::{
    NodeAggregationOutputData, VK_ENCODING_LENGTH,
};
use advanced_circuit_component::testing::create_test_artifacts;
use advanced_circuit_component::traits::*;
use advanced_circuit_component::vm::structural_eq::*;
use cs_derive::*;
use derivative::Derivative;
use std::collections::BTreeMap;

pub const ORACLE_CIRCUIT_TYPES_NUM: usize = 6;
pub const ALL_AGGREGATION_TYPES: [OracleCircuitType; ORACLE_CIRCUIT_TYPES_NUM] = [
    OracleCircuitType::AggregationNull,
    OracleCircuitType::Aggregation1,
    OracleCircuitType::Aggregation2,
    OracleCircuitType::Aggregation3,
    OracleCircuitType::Aggregation4,
    OracleCircuitType::Aggregation5,
];

pub struct OracleAggregationCircuit<'a, E: Engine> {
    pub(crate) oracle_inputs_data: Vec<OracleOutputDataWitness<E>>,
    pub(crate) proof_witnesses: Vec<(OracleCircuitType, UniformProof<E>)>,

    pub(crate) vks_set: BTreeMap<OracleCircuitType, VkEncodeInfo<E>>,
    pub(crate) vk_encoding_witnesses: Vec<[E::Fr; VK_ENCODING_LENGTH]>,

    pub output: Option<OracleAggregationOutputDataWitness<E>>,
    pub padding_component: PaddingCryptoComponent<E>,
    pub(crate) params: &'a CommonCryptoParams<E>,
}

impl OracleAggregationCircuit<'_, Bn256> {
    pub fn circuit_default(agg_num: usize, total_oracle_type_num: usize) -> Self {
        Self {
            oracle_inputs_data: vec![
                <OracleOutputData<Bn256> as CSWitnessable<Bn256>>::placeholder_witness(
                );
                agg_num
            ],
            proof_witnesses: vec![(0.into(), UniformProof::empty()); agg_num],
            vks_set: (0..total_oracle_type_num)
                .map(|n| (n.into(), Default::default()))
                .collect(),
            vk_encoding_witnesses: vec![
                [Default::default(); VK_ENCODING_LENGTH];
                total_oracle_type_num
            ],
            params: &COMMON_CRYPTO_PARAMS,
            output: None,
            padding_component: PaddingCryptoComponent::default(),
        }
    }

    pub fn generate(
        oracle_inputs_data: Vec<OracleOutputDataWitness<Bn256>>,
        proof_witnesses: Vec<(OracleCircuitType, UniformProof<Bn256>)>,
        vks: BTreeMap<OracleCircuitType, VerificationKey<Bn256, UniformCircuit<Bn256>>>,
        padding_proof: UniformProof<Bn256>,
    ) -> Self {
        let num_proofs_to_aggregate = oracle_inputs_data.len();
        assert_eq!(num_proofs_to_aggregate, proof_witnesses.len());
        for (circuit_type, proof) in proof_witnesses.iter() {
            let vk = vks.get(circuit_type).unwrap();
            assert!(
                better_better_cs::verifier::verify::<_, _, RescueTranscriptForRecursion<'_, _>>(
                    vk,
                    proof,
                    Some(COMMON_CRYPTO_PARAMS.recursive_transcript_params()),
                )
                .expect("must try to verify a proof"),
                "proof and VK must be valid"
            );
        }

        let padding_vk = vks
            .get(&OracleCircuitType::AggregationNull)
            .cloned()
            .unwrap();
        let vks_set = vks
            .into_iter()
            .map(|(t, vk)| (t, VkEncodeInfo::new(vk)))
            .collect::<BTreeMap<OracleCircuitType, _>>();
        let vk_encoding_witnesses = proof_witnesses
            .iter()
            .map(|(t, _)| vks_set.get(t).unwrap().vk_encoding_witness)
            .collect::<Vec<_>>();

        let mut witness = Self {
            oracle_inputs_data,
            vks_set,
            vk_encoding_witnesses,
            proof_witnesses,
            params: &COMMON_CRYPTO_PARAMS,
            output: None,
            padding_component: PaddingCryptoComponent::default(),
        };
        let agg_params = witness.params.aggregation_params();
        let rns_params = witness.params.rns_params.clone();
        let commit_hash = witness.params.poseidon_hash();
        let transcript_params = &witness.params.rescue_params;
        let padding = PaddingCryptoComponent::new(
            padding_vk,
            padding_proof,
            &commit_hash,
            transcript_params,
            &rns_params,
        );
        let params = (
            num_proofs_to_aggregate,
            rns_params,
            agg_params,
            padding.clone(),
            None,
        );
        let (mut cs, ..) = create_test_artifacts();
        let (_public_input, public_input_data) =
            aggregate_oracle_proofs(&mut cs, Some(&witness), &commit_hash, params)
                .expect("Failed to oracle aggregate");

        witness.output = public_input_data.create_witness();
        witness.padding_component = padding;
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
pub struct OracleAggregationOutputData<E: Engine> {
    pub oracle_vks_hash: Num<E>,
    pub guardian_set_hash: Num<E>,
    pub prices_commitment: OraclePricesCommitment<E>,
    pub earliest_publish_time: Num<E>,
    pub aggregation_output_data: NodeAggregationOutputData<E>,
}

impl<E: Engine> CircuitEmpty<E> for OracleAggregationOutputData<E> {
    fn empty() -> Self {
        Self {
            oracle_vks_hash: Num::zero(),
            guardian_set_hash: Num::zero(),
            prices_commitment: CircuitEmpty::empty(),
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
    pub earliest_publish_time: Num<E>,
    pub prices_commitment: OraclePricesCommitment<E>,
}

impl<E: Engine> CircuitEmpty<E> for OracleOutputData<E> {
    fn empty() -> Self {
        Self {
            guardian_set_hash: Num::zero(),
            earliest_publish_time: Num::zero(),
            prices_commitment: CircuitEmpty::empty(),
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
pub struct OraclePricesCommitment<E: Engine> {
    pub prices_commitment: Num<E>,
    pub prices_num: Num<E>,
    pub prices_commitment_base_sum: Num<E>, // public input
}

impl<E: Engine> CircuitEmpty<E> for OraclePricesCommitment<E> {
    fn empty() -> Self {
        Self {
            prices_commitment: Num::zero(),
            prices_num: Num::zero(),
            prices_commitment_base_sum: Num::zero(),
        }
    }
}

#[derive(
    Debug, Clone, Copy, Ord, PartialOrd, Eq, PartialEq, serde::Serialize, serde::Deserialize,
)]
pub enum OracleCircuitType {
    AggregationNull = 0, // For padding
    Aggregation1 = 1,
    Aggregation2 = 2,
    Aggregation3 = 3,
    Aggregation4 = 4,
    Aggregation5 = 5,
}

impl From<usize> for OracleCircuitType {
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

impl Default for OracleCircuitType {
    fn default() -> Self {
        Self::AggregationNull
    }
}
