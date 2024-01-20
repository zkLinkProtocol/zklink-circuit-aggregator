use crate::bellman::plonk::better_better_cs::cs::{Circuit, Gate, GateInternal};
use crate::bellman::plonk::better_better_cs::gates::selector_optimized_with_d_next::SelectorOptimizedWidth4MainGateWithDNext;
use crate::crypto_utils::PaddingCryptoComponent;
use crate::oracle_aggregation::witness::{
    OracleAggregationCircuit, OracleAggregationOutputData, OracleCircuitType, OracleOutputData,
};
use crate::{ALL_AGGREGATION_TYPES, ORACLE_CIRCUIT_TYPES_NUM};
use advanced_circuit_component::franklin_crypto::bellman::plonk::better_better_cs::cs::ConstraintSystem;
use advanced_circuit_component::franklin_crypto::bellman::{Engine, SynthesisError};
use advanced_circuit_component::franklin_crypto::plonk::circuit::allocated_num::{AllocatedNum, Num};
use advanced_circuit_component::franklin_crypto::plonk::circuit::bigint::RnsParameters;
use advanced_circuit_component::franklin_crypto::plonk::circuit::boolean::Boolean;
use advanced_circuit_component::franklin_crypto::plonk::circuit::custom_rescue_gate::Rescue5CustomGate;
use advanced_circuit_component::franklin_crypto::plonk::circuit::tables::inscribe_default_range_table_for_bit_width_over_first_three_columns;
use advanced_circuit_component::franklin_crypto::plonk::circuit::Assignment;
use advanced_circuit_component::circuit_structures::traits::CircuitArithmeticRoundFunction;
use advanced_circuit_component::circuit_structures::utils::can_not_be_false_if_flagged;
use advanced_circuit_component::glue::optimizable_queue::commit_encodable_item;
use advanced_circuit_component::glue::prepacked_long_comparison;
use advanced_circuit_component::project_ref;
use advanced_circuit_component::recursion::node_aggregation::{aggregate_generic_inner, NodeAggregationOutputData};
use advanced_circuit_component::recursion::recursion_tree::AggregationParameters;
use advanced_circuit_component::recursion::transcript::TranscriptGadget;
use advanced_circuit_component::recursion::RANGE_CHECK_TABLE_BIT_WIDTH;
use advanced_circuit_component::rescue_poseidon::HashParams;
use advanced_circuit_component::traits::CSAllocatable;
use advanced_circuit_component::traits::CircuitEmpty;
use advanced_circuit_component::vm::partitioner::{smart_and, smart_or};
use advanced_circuit_component::vm::primitives::small_uints::IntoFr;
use crate::key_manager::enforce_commit_vks_commitments;

impl<'a, E: Engine> Circuit<E> for OracleAggregationCircuit<'a, E> {
    type MainGate = SelectorOptimizedWidth4MainGateWithDNext;

    fn synthesize<CS: ConstraintSystem<E>>(&self, cs: &mut CS) -> Result<(), SynthesisError> {
        let agg_params = self.params.aggregation_params();
        let rns_params = self.params.rns_params.clone();
        let commit_hash = self.params.poseidon_hash();
        let transcript_params = &self.params.rescue_params;

        let padding = PaddingCryptoComponent::new(
            self.padding_component.padding_vk.clone(),
            self.padding_component.padding_proof.clone(),
            &commit_hash,
            transcript_params,
            &rns_params,
        );
        let params = (self.oracle_inputs_data.len(), rns_params, agg_params, padding, None);
        let (_public_input, _input_data) =
            aggregate_oracle_proofs(cs, Some(self), &commit_hash, params)?;
        Ok(())
    }

    fn declare_used_gates() -> Result<Vec<Box<dyn GateInternal<E>>>, SynthesisError> {
        Ok(vec![
            SelectorOptimizedWidth4MainGateWithDNext.into_internal(),
            Rescue5CustomGate.into_internal(),
        ])
    }
}

pub fn aggregate_oracle_proofs<
    E: Engine,
    CS: ConstraintSystem<E>,
    T: TranscriptGadget<E>,
    P: HashParams<E, 2, 3>,
    R: CircuitArithmeticRoundFunction<E, 2, 3, StateElement = Num<E>>,
>(
    cs: &mut CS,
    witness: Option<&OracleAggregationCircuit<E>>,
    commit_function: &R,
    params: (
        usize,
        RnsParameters<E, E::Fq>,
        AggregationParameters<E, T, P, 2, 3>,
        PaddingCryptoComponent<E>,
        Option<[E::G2Affine; 2]>,
    ),
) -> Result<(AllocatedNum<E>, OracleAggregationOutputData<E>), SynthesisError> {
    let (
        num_proofs_to_aggregate,
        rns_params,
        aggregation_params,
        PaddingCryptoComponent {
            padding_vk_commitment,
            padding_vk_encoding,
            padding_public_input,
            padding_proof,
            ..
        },
        g2_elements,
    ) = params;
    inscribe_default_range_table_for_bit_width_over_first_three_columns(cs, RANGE_CHECK_TABLE_BIT_WIDTH)?;

    // prepare all witness
    let oracle_inputs_data = project_ref!(witness, oracle_inputs_data).cloned();
    let aggregation_proofs = project_ref!(witness, proof_witnesses).cloned();
    let vks_raw_elements_witness = project_ref!(witness, vk_encoding_witnesses).cloned();
    let vks_set = project_ref!(witness, vks_set).cloned();

    // prepare vk_commitments circuit variables
    let mut vk_commitments = Vec::with_capacity(ORACLE_CIRCUIT_TYPES_NUM);
    for circuit_type in ALL_AGGREGATION_TYPES {
        let circuit_type_num = Num::Constant(IntoFr::<E>::into_fr(circuit_type as u8));
        let vk_commitment = Num::alloc(
            cs,
            vks_set.as_ref().map(|info| info.get(&circuit_type).unwrap().vk_commitment),
        )?;
        vk_commitments.push((circuit_type_num, vk_commitment));
    }

    // check all recursive inputs(oracle circuit output data)
    let mut used_key_commitments = Vec::with_capacity(num_proofs_to_aggregate);
    let mut inputs = Vec::with_capacity(num_proofs_to_aggregate);
    let (mut guardian_set_hash, mut is_correct_guardian_set_hash) = (Num::zero(), vec![Boolean::constant(true)]);
    let mut final_price_commitment = Num::zero();
    let (mut earliest_publish_time, mut is_correct_earliest_publish_time) = (Num::zero(), vec![Boolean::constant(true)]);
    let mut last_oracle_input_data = OracleOutputData::empty();
    for proof_idx in 0..num_proofs_to_aggregate {
        let used_circuit_type = Num::alloc(
            cs,
            aggregation_proofs.as_ref().map(|a| IntoFr::<E>::into_fr(a[proof_idx].0 as u8)),
        )?;
        let is_padding = {
            let padding_type = Num::Constant(IntoFr::<E>::into_fr(
                OracleCircuitType::AggregationNull as u8,
            ));
            Num::equals(cs, &padding_type, &used_circuit_type)?
        };
        let oracle_input_data = oracle_inputs_data
            .as_ref()
            .map(|data| data[proof_idx].clone());
        let oracle_input_data = OracleOutputData::alloc_from_witness(cs, oracle_input_data)?;
        let input_commitment = commit_encodable_item(cs, &oracle_input_data, commit_function)?;
        let input = Num::conditionally_select(
            cs,
            &is_padding,
            &Num::Constant(padding_public_input[proof_idx]),
            &input_commitment,
        )?;

        let mut vk_commitment_to_use = Num::Constant(padding_vk_commitment);
        let mut vk_existing_flags = Vec::with_capacity(vk_commitments.len());
        for (circuit_type, vk_commitment) in vk_commitments.iter() {
            let is_this = Num::equals(cs, circuit_type, &used_circuit_type)?;
            vk_commitment_to_use =
                Num::conditionally_select(cs, &is_this, vk_commitment, &vk_commitment_to_use)?;
            vk_existing_flags.push(is_this);
        }
        let existing_vk = smart_or(cs, &vk_existing_flags)?;
        can_not_be_false_if_flagged(cs, &existing_vk, &Boolean::constant(true))?;

        guardian_set_hash = oracle_input_data.guardian_set_hash;
        if proof_idx == 0 {
            earliest_publish_time = oracle_input_data.earliest_publish_time;
        } else {
            is_correct_guardian_set_hash.push(Num::equals(
                cs,
                &last_oracle_input_data.guardian_set_hash,
                &oracle_input_data.guardian_set_hash,
            )?);
            let (is_equal, is_greater) = prepacked_long_comparison(
                cs,
                &[oracle_input_data.earliest_publish_time],
                &[last_oracle_input_data.earliest_publish_time],
                &[32],
            )?;
            let is_equal_or_greater = Boolean::or(cs, &is_equal, &is_greater)?;
            is_correct_earliest_publish_time.push(is_equal_or_greater);
        }
        let acc_price_commitment = final_price_commitment
            .square(cs)?
            .add(cs, &oracle_input_data.final_price_commitment)?;
        final_price_commitment = Num::conditionally_select(
            cs,
            &is_padding,
            &final_price_commitment,
            &acc_price_commitment,
        )?;

        used_key_commitments.push(vk_commitment_to_use);
        inputs.push(input);
        last_oracle_input_data = oracle_input_data;
    }
    assert_eq!(used_key_commitments.len(), inputs.len());
    assert_eq!(used_key_commitments.len(), num_proofs_to_aggregate);
    let is_correct_guardian_set_hash = smart_and(cs, &is_correct_guardian_set_hash)?;
    Boolean::enforce_equal(cs, &is_correct_guardian_set_hash, &Boolean::constant(true))?;
    let is_earliest_publish_time = smart_and(cs, &is_correct_earliest_publish_time)?;
    Boolean::enforce_equal(cs, &is_earliest_publish_time, &Boolean::constant(true))?;

    // do actual aggregation work
    let [[pair_with_generator_x, pair_with_generator_y], [pair_with_x_x, pair_with_x_y]] =
        aggregate_generic_inner::<_, _, _, _, _, _, true>(
            cs,
            used_key_commitments,
            inputs,
            aggregation_proofs.map(|proofs| proofs.into_iter().unzip::<_, _, Vec<_>, Vec<_>>().1),
            aggregation_params,
            &rns_params,
            padding_proof,
            None, // no results to aggregate on top
            commit_function,
            vks_raw_elements_witness,
            padding_vk_encoding,
            g2_elements,
            num_proofs_to_aggregate,
        )?;

    // collect oracle aggregation output data
    let public_input_data = OracleAggregationOutputData {
        oracle_vks_hash: enforce_commit_vks_commitments(cs, vk_commitments, commit_function)?,
        guardian_set_hash,
        final_price_commitment,
        earliest_publish_time,
        aggregation_output_data: NodeAggregationOutputData {
            pair_with_x_x,
            pair_with_x_y,
            pair_with_generator_x,
            pair_with_generator_y,
        },
    };

    let input_commitment = commit_encodable_item(cs, &public_input_data, commit_function)?;
    let public_input = AllocatedNum::alloc_input(cs, || input_commitment.get_value().grab())?;
    public_input.enforce_equal(cs, &input_commitment.get_variable())?;

    Ok((public_input, public_input_data))
}

#[cfg(test)]
mod tests {
    use crate::crypto_utils::PaddingCryptoComponent;
    use crate::oracle_aggregation::aggregation::aggregate_oracle_proofs;
    use advanced_circuit_component::franklin_crypto::bellman::bn256::Fq;
    use advanced_circuit_component::franklin_crypto::bellman::plonk::better_better_cs::cs::{ConstraintSystem, PlonkCsWidth4WithNextStepAndCustomGatesParams, PolyIdentifier, TrivialAssembly};
    use advanced_circuit_component::franklin_crypto::bellman::plonk::better_better_cs::gates::selector_optimized_with_d_next::SelectorOptimizedWidth4MainGateWithDNext;
    use advanced_circuit_component::franklin_crypto::bellman::plonk::better_better_cs::lookup_tables::LookupTableApplication;
    use advanced_circuit_component::franklin_crypto::plonk::circuit::bigint::RnsParameters;
    use advanced_circuit_component::recursion::get_base_placeholder_point_for_accumulators;
    use advanced_circuit_component::recursion::recursion_tree::AggregationParameters;
    use advanced_circuit_component::recursion::transcript::GenericTranscriptGadget;
    use advanced_circuit_component::rescue_poseidon::PoseidonParams;
    use advanced_circuit_component::testing::Bn256;
    use advanced_circuit_component::traits::GenericHasher;
    use advanced_circuit_component::utils::bn254_rescue_params;
    use advanced_circuit_component::vm::tables::BitwiseLogicTable;
    use advanced_circuit_component::vm::VM_BITWISE_LOGICAL_OPS_TABLE_NAME;

    type ActualConstraintSystem = TrivialAssembly<
        Bn256,
        PlonkCsWidth4WithNextStepAndCustomGatesParams,
        SelectorOptimizedWidth4MainGateWithDNext,
    >;

    fn generate_test_constraint_system() -> ActualConstraintSystem {
        let (mut cs, _, _) = advanced_circuit_component::testing::create_test_artifacts_with_optimized_gate();
        let columns3 = vec![
            PolyIdentifier::VariablesPolynomial(0),
            PolyIdentifier::VariablesPolynomial(1),
            PolyIdentifier::VariablesPolynomial(2),
        ];

        if cs.get_table(VM_BITWISE_LOGICAL_OPS_TABLE_NAME).is_err() {
            let name = VM_BITWISE_LOGICAL_OPS_TABLE_NAME;
            let bitwise_logic_table = LookupTableApplication::new(
                name,
                BitwiseLogicTable::new(&name, 8),
                columns3.clone(),
                None,
                true,
            );
            cs.add_table(bitwise_logic_table).unwrap();
        };
        cs
    }

    #[test]
    fn test_oracle_aggregation() {
        let mut cs = generate_test_constraint_system();
        let commit_hash_params = PoseidonParams::default();
        let commit_hash = GenericHasher::new_from_params(&commit_hash_params);
        let rns_params = RnsParameters::<Bn256, Fq>::new_for_field(68, 110, 4);
        let transcript_params = bn254_rescue_params();

        let padding = PaddingCryptoComponent::default();
        let agg_params = AggregationParameters::<_, GenericTranscriptGadget<_, _, 2, 3>, _, 2, 3> {
            base_placeholder_point: get_base_placeholder_point_for_accumulators(),
            transcript_params: transcript_params.clone(),
            hash_params: transcript_params,
        };

        let params = (1usize, rns_params, agg_params, padding, None);
        aggregate_oracle_proofs(&mut cs, None, &commit_hash, params).unwrap();
        println!("circuit contains {} gates", cs.n());
        assert!(cs.is_satisfied());
    }
}
