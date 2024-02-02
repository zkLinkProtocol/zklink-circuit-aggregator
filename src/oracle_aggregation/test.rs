use crate::params::{RescueTranscriptForRecursion, COMMON_CRYPTO_PARAMS};
use crate::{OracleAggregationCircuit, UniformProof, UniformVerificationKey};
use advanced_circuit_component::franklin_crypto::bellman::bn256::Bn256;
use advanced_circuit_component::franklin_crypto::bellman::plonk::better_better_cs::cs::PlonkCsWidth4WithNextStepAndCustomGatesParams;
use base64::Engine as _;
use std::collections::BTreeMap;
use zklink_oracle::pythnet_sdk::wire::v1::AccumulatorUpdateData;
use zklink_oracle::witness::{OracleOutputDataWitness, OraclePricesSummarizeWitness};

#[test]
#[ignore]
fn test_oracle_aggregation_circuit() {
    use zklink_oracle::pyth::PriceOracle;

    let data = new_data(2);
    let test_circuit = PriceOracle::<Bn256, 3>::new(data, vec![[0u8; 20]], 0).unwrap();
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
        (0, vk.clone()),
        (1, vk.clone()),
        (2, vk.clone()),
        (3, vk.clone()),
        (4, vk.clone()),
        (5, vk),
    ]);
    let oracle_aggregation_circuit = OracleAggregationCircuit::generate(
        vec![oracle_inputs_data],
        vec![(1, proof.clone())],
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

fn new_data(num: usize) -> Vec<AccumulatorUpdateData> {
    let accumulator_update_data = {
        // base64 encoded hex from hermes API /api/latest_vaas (https://hermes.pyth.network/docs/#/rest/latest_vaas)
        let hex = "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";
        let bytes = base64::engine::general_purpose::STANDARD
            .decode(hex)
            .unwrap();
        AccumulatorUpdateData::try_from_slice(bytes.as_ref()).unwrap()
    };

    (0..num)
        .map(|_| accumulator_update_data.clone())
        .collect::<Vec<_>>()
}
