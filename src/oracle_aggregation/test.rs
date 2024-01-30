use crate::params::{RescueTranscriptForRecursion, COMMON_CRYPTO_PARAMS};
use crate::{OracleAggregationCircuit, UniformProof, UniformVerificationKey};
use advanced_circuit_component::franklin_crypto::bellman::bn256::Bn256;
use advanced_circuit_component::franklin_crypto::bellman::plonk::better_better_cs::cs::PlonkCsWidth4WithNextStepAndCustomGatesParams;
use std::collections::BTreeMap;
use zklink_oracle::witness::{OracleOutputDataWitness, OraclePricesSummarizeWitness};

#[test]
fn test_oracle_aggregation_circuit() {
    use crate::OracleCircuitType::*;
    use zklink_oracle::pyth::PriceOracle;

    let test_circuit = PriceOracle::<Bn256, 0, 0>::new(vec![], vec![[0u8; 20]]).unwrap();
    let oracle_inputs_data = {
        let data = test_circuit.public_input_data();
        OracleOutputDataWitness {
            guardian_set_hash: data.guardian_set_hash,
            prices_summarize: OraclePricesSummarizeWitness {
                commitment: data.prices_summarize.commitment,
                num: data.prices_summarize.num,
                commitment_base_sum: data.prices_summarize.commitment_base_sum,
                _marker: Default::default(),
            },
            earliest_publish_time: data.earliest_publish_time,
            _marker: Default::default(),
        }
    };
    let transcript = COMMON_CRYPTO_PARAMS.recursive_transcript_params();
    let (proof, vk) = circuit_testing::prove_and_verify_circuit_for_params::<
        Bn256,
        _,
        PlonkCsWidth4WithNextStepAndCustomGatesParams,
        RescueTranscriptForRecursion<Bn256>,
        true,
    >(test_circuit, Some(transcript))
    .unwrap();
    let proof: UniformProof<Bn256> = unsafe { std::mem::transmute(proof) };
    let vk: UniformVerificationKey<Bn256> = unsafe { std::mem::transmute(vk) };
    let vks = BTreeMap::from([
        (AggregationNull, vk.clone()),
        (Aggregation1, vk.clone()),
        (Aggregation2, vk.clone()),
        (Aggregation3, vk.clone()),
        (Aggregation4, vk.clone()),
        (Aggregation5, vk),
    ]);
    let oracle_aggregation_circuit = OracleAggregationCircuit::generate(
        vec![oracle_inputs_data],
        vec![(Aggregation1, proof.clone())],
        vks,
        proof,
    );
    circuit_testing::prove_and_verify_circuit_for_params::<
        Bn256,
        _,
        PlonkCsWidth4WithNextStepAndCustomGatesParams,
        RescueTranscriptForRecursion<Bn256>,
        true,
    >(oracle_aggregation_circuit, Some(transcript))
    .unwrap();
}
