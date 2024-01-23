use std::collections::BTreeMap;
use advanced_circuit_component::franklin_crypto::bellman::plonk::commitments::transcript::keccak_transcript::RollingKeccakTranscript;
use zklink_oracle::ZkLinkOracle;
use advanced_circuit_component::franklin_crypto::bellman::bn256::{Bn256, Fr};
use advanced_circuit_component::franklin_crypto::bellman::plonk::better_better_cs::cs::PlonkCsWidth4WithNextStepAndCustomGatesParams;
use crate::{FinalAggregationCircuit, OracleAggregationCircuit, OracleOutputDataWitness, UniformProof, UniformVerificationKey};
use crate::params::{COMMON_CRYPTO_PARAMS, RescueTranscriptForRecursion};

#[test]
fn test_final_aggregation_circuit() {
    use crate::OracleCircuitType::*;

    println!("---------------------------oracle circuit start--------------------------------");
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

    println!("---------------------------oracle aggregation circuit start--------------------------------");
    let proof: UniformProof<Bn256> = unsafe { std::mem::transmute(proof) };
    let vk: UniformVerificationKey<Bn256> = unsafe { std::mem::transmute(vk) };
    let oracle_aggregation_circuit = OracleAggregationCircuit::generate(
        vec![oracle_inputs_data],
        vec![(Aggregation1, proof.clone())],
        (0..crate::oracle_aggregation::ORACLE_CIRCUIT_TYPES_NUM).map(|n| (n.into(), vk.clone())).collect(),
        proof
    );
    let oracle_agg_output = oracle_aggregation_circuit.output.clone().unwrap();
    let (oracle_aggregation_proof, oracle_agg_vk) =
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

    println!("---------------------------block aggregation circuit start--------------------------------");
    let (block_aggregation_circuit, aggregation_storage) = recursive_aggregation_circuit::test_utils::create_test_block_aggregation_circuit();
    let block_output_data = aggregation_storage.output;
    let (proof, vk ) =
        circuit_testing::prove_and_verify_circuit_for_params::<
            Bn256,
            _,
            PlonkCsWidth4WithNextStepAndCustomGatesParams,
            RescueTranscriptForRecursion<Bn256>,
            true
        >(
            block_aggregation_circuit,
            Some(transcript),
        ).unwrap();

    println!("---------------------------final aggregation circuit start--------------------------------");
    let oracle_aggregation_proof: UniformProof<Bn256> = unsafe { std::mem::transmute(oracle_aggregation_proof) };
    let oracle_agg_vk: UniformVerificationKey<Bn256> = unsafe { std::mem::transmute(oracle_agg_vk) };
    let block_agg_proof: UniformProof<Bn256> = unsafe { std::mem::transmute(proof) };
    let block_agg_vk: UniformVerificationKey<Bn256> = unsafe { std::mem::transmute(vk) };
    let oracle_aggregation_circuit = FinalAggregationCircuit::generate(
        block_output_data,
        (0, block_agg_proof),
        BTreeMap::from([(0, block_agg_vk)]),
        vec![oracle_agg_output],
        vec![(0, oracle_aggregation_proof)],
        BTreeMap::from([(0, oracle_agg_vk)]),
    );
    circuit_testing::prove_and_verify_circuit_for_params::<
        Bn256,
        _,
        PlonkCsWidth4WithNextStepAndCustomGatesParams,
        RollingKeccakTranscript<Fr>,
        true
    >(
        oracle_aggregation_circuit,
        None
    ).unwrap();
}
