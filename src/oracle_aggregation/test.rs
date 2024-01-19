use std::collections::BTreeMap;
use advanced_circuit_component::franklin_crypto::bellman::plonk::better_better_cs::cs::PlonkCsWidth4WithNextStepAndCustomGatesParams;
use crate::{OracleAggregationCircuit, OracleOutputDataWitness, UniformProof, UniformVerificationKey};
use crate::bellman::bn256::Bn256;
use crate::params::{COMMON_CRYPTO_PARAMS, RescueTranscriptForRecursion};

#[test]
fn test_all_aggregation_circuit() {
    use crate::OracleCircuitType::*;
    use zklink_oracle::ZkLinkOracle;

    let test_circuit = ZkLinkOracle::<Bn256, 0, 0>::new(
        vec![],
        vec![[0u8; 20]]
    ).unwrap();
    let oracle_inputs_data = {
        let data = test_circuit.public_input_data();
        OracleOutputDataWitness {
            guardian_set_hash: data.guardian_set_hash,
            final_price_commitment: data.prices_commitment,
            earliest_publish_time: data.earliest_publish_time,
            _marker: Default::default(),
        }
    };
    let transcript = COMMON_CRYPTO_PARAMS.recursive_transcript_params();
    let (proof, vk ) =
        circuit_testing::prove_and_verify_circuit_for_params::<
            Bn256,
            _,
            PlonkCsWidth4WithNextStepAndCustomGatesParams,
            RescueTranscriptForRecursion<Bn256>,
            true
        >(
            test_circuit,
            Some(transcript),
        ).unwrap();
    let proof: UniformProof<Bn256> = unsafe { std::mem::transmute(proof) };
    let vk: UniformVerificationKey<Bn256> = unsafe { std::mem::transmute(vk) };
    let vks = BTreeMap::from([(Aggregation1, vk.clone()), (AggregationNull, vk)]);
    let oracle_aggregation_circuit = OracleAggregationCircuit::generate(
        vec![oracle_inputs_data],
        vec![(Aggregation1, proof.clone())],
        vks,
        proof
    );
    circuit_testing::prove_and_verify_circuit_for_params::<
        Bn256,
        _,
        PlonkCsWidth4WithNextStepAndCustomGatesParams,
        RescueTranscriptForRecursion<Bn256>,
        true
    >(
        oracle_aggregation_circuit,
        Some(transcript)
    ).unwrap();
}
