use crate::bellman::plonk::better_better_cs::cs::{Gate, GateInternal, RANGE_CHECK_SINGLE_APPLICATION_TABLE_NAME};
use crate::crypto_utils::PaddingCryptoComponent;
use crate::final_aggregation::witness::{
    FinalAggregationCircuit, FinalAggregationOutputData,
    OracleOnChainData, VksCompositionData,
};
use crate::oracle_aggregation::OracleAggregationOutputData;
use advanced_circuit_component::franklin_crypto::bellman::plonk::better_better_cs::cs::{Circuit, ConstraintSystem};
use advanced_circuit_component::franklin_crypto::bellman::plonk::better_better_cs::gates::selector_optimized_with_d_next::SelectorOptimizedWidth4MainGateWithDNext;
use advanced_circuit_component::franklin_crypto::bellman::{Engine, PrimeField, SynthesisError};
use advanced_circuit_component::franklin_crypto::plonk::circuit::allocated_num::{AllocatedNum, Num};
use advanced_circuit_component::franklin_crypto::plonk::circuit::bigint::RnsParameters;
use advanced_circuit_component::franklin_crypto::plonk::circuit::boolean::Boolean;
use advanced_circuit_component::franklin_crypto::plonk::circuit::custom_rescue_gate::Rescue5CustomGate;
use advanced_circuit_component::franklin_crypto::plonk::circuit::tables::inscribe_default_range_table_for_bit_width_over_first_three_columns;
use advanced_circuit_component::franklin_crypto::plonk::circuit::Assignment;
use advanced_circuit_component::franklin_crypto::plonk::circuit::hashes_with_tables::keccak::gadgets::Keccak256Gadget;
use advanced_circuit_component::franklin_crypto::plonk::circuit::linear_combination::LinearCombination;
use advanced_circuit_component::circuit_structures::traits::CircuitArithmeticRoundFunction;
use advanced_circuit_component::circuit_structures::utils::can_not_be_false_if_flagged;
use advanced_circuit_component::glue::optimizable_queue::{commit_encodable_item, commit_variable_length_encodable_item};
use advanced_circuit_component::glue::prepacked_long_comparison;
use advanced_circuit_component::recursion::node_aggregation::{aggregate_generic_inner, NodeAggregationOutputData};
use advanced_circuit_component::recursion::recursion_tree::{AggregationParameters, NUM_LIMBS};
use advanced_circuit_component::recursion::transcript::TranscriptGadget;
use advanced_circuit_component::recursion::RANGE_CHECK_TABLE_BIT_WIDTH;
use advanced_circuit_component::rescue_poseidon::HashParams;
use advanced_circuit_component::scheduler::block_header::keccak_output_into_bytes;
use advanced_circuit_component::traits::{CSAllocatable, CircuitEmpty};
use advanced_circuit_component::utils::compute_shifts;
use advanced_circuit_component::vm::partitioner::smart_or;
use advanced_circuit_component::vm::primitives::small_uints::IntoFr;
use advanced_circuit_component::vm::tables::BitwiseLogicTable;
use recursive_aggregation_circuit::BlockAggregationOutputData;
use crate::bellman::plonk::better_better_cs::data_structures::PolyIdentifier;
use crate::bellman::plonk::better_better_cs::lookup_tables::LookupTableApplication;
use crate::franklin_crypto::plonk::circuit::bigint_new::BITWISE_LOGICAL_OPS_TABLE_NAME;
use crate::key_manager::enforce_commit_vks_commitments;

const MAX_AGGREGATE_NUM: u8 = 5 * 36;
const GUARDIAN_SET_INDEX: u8 = 3;

impl<'a, E: Engine> Circuit<E> for FinalAggregationCircuit<'a, E> {
    type MainGate = SelectorOptimizedWidth4MainGateWithDNext;

    fn synthesize<CS: ConstraintSystem<E>>(&self, cs: &mut CS) -> Result<(), SynthesisError> {
        let agg_params = self.params.aggregation_params();
        let rns_params = self.params.rns_params.clone();
        let commit_hash = self.params.poseidon_hash();

        let padding = PaddingCryptoComponent::default();
        let params = (
            self.oracle_proof.len(),
            rns_params,
            agg_params,
            padding,
            Default::default(),
            None,
        );
        let (_public_input, _input_data) = final_aggregation(cs, self, &commit_hash, params)?;
        Ok(())
    }

    fn declare_used_gates() -> Result<Vec<Box<dyn GateInternal<E>>>, SynthesisError> {
        Ok(vec![
            SelectorOptimizedWidth4MainGateWithDNext.into_internal(),
            Rescue5CustomGate.into_internal(),
        ])
    }
}

pub fn final_aggregation<
    E: Engine,
    CS: ConstraintSystem<E>,
    T: TranscriptGadget<E>,
    P: HashParams<E, 2, 3>,
    R: CircuitArithmeticRoundFunction<E, 2, 3, StateElement = Num<E>>,
>(
    cs: &mut CS,
    witness: &FinalAggregationCircuit<E>,
    commit_function: &R,
    params: (
        usize,
        RnsParameters<E, E::Fq>,
        AggregationParameters<E, T, P, 2, 3>,
        PaddingCryptoComponent<E>,
        Vec<(
            [E::Fr; NUM_LIMBS],
            [E::Fr; NUM_LIMBS],
            [E::Fr; NUM_LIMBS],
            [E::Fr; NUM_LIMBS],
        )>,
        Option<[E::G2Affine; 2]>,
    ),
) -> Result<(AllocatedNum<E>, FinalAggregationOutputData<E>), SynthesisError> {
    let (
        num_proofs_aggregated_oracle,
        rns_params,
        aggregation_params,
        PaddingCryptoComponent {
            padding_vk_commitment: _,
            padding_vk_encoding,
            padding_public_input: _,
            padding_proof,
            ..
        },
        _padding_aggregation_sets,
        g2_elements,
    ) = params;
    if cs.get_table(BITWISE_LOGICAL_OPS_TABLE_NAME).is_err() {
        let columns3 = vec![
            PolyIdentifier::VariablesPolynomial(0),
            PolyIdentifier::VariablesPolynomial(1),
            PolyIdentifier::VariablesPolynomial(2),
        ];
        let name = BITWISE_LOGICAL_OPS_TABLE_NAME;
        let bitwise_logic_table = LookupTableApplication::new(
            name,
            BitwiseLogicTable::new(name, 8),
            columns3.clone(),
            None,
            true,
        );
        cs.add_table(bitwise_logic_table)?;
    };
    inscribe_default_range_table_for_bit_width_over_first_three_columns(cs, RANGE_CHECK_TABLE_BIT_WIDTH)?;

    let block_aggregation_result = witness.block_aggregation_result.clone();
    let oracle_aggregation_results = witness.oracle_aggregation_results.clone();
    let (block_circuit_type, block_aggregation_proof) = witness.block_proof.clone();
    let oracle_aggregation_proof = witness.oracle_proof.clone();
    let oracle_vks_info = witness.oracle_vks_set.clone();
    let block_vks_info = witness.block_vks_set.clone();

    let mut vks_raw_elements_witness = vec![];
    vks_raw_elements_witness.push(block_vks_info.get(&block_circuit_type).unwrap().vk_encoding_witness);
    for (circuit_type, _) in &oracle_aggregation_proof {
        vks_raw_elements_witness.push(oracle_vks_info.get(circuit_type).unwrap().vk_encoding_witness);
    }

    // prepare vk_commitments circuit variables
    let mut oracle_vk_commitments = Vec::with_capacity(oracle_vks_info.len());
    for (circuit_type, vk_info) in oracle_vks_info {
        let circuit_type = Num::<E>::Constant(IntoFr::<E>::into_fr(circuit_type as u8));
        let vk_commitment = Num::alloc(cs, Some(vk_info.vk_commitment))?;
        oracle_vk_commitments.push((circuit_type, vk_commitment));
    }
    let mut block_vk_commitments = Vec::with_capacity(block_vks_info.len());
    for (circuit_type, vk_info) in block_vks_info {
        let circuit_type = Num::Constant(IntoFr::<E>::into_fr(circuit_type as u8));
        let vk_commitment = Num::alloc(cs, Some(vk_info.vk_commitment))?;
        block_vk_commitments.push((circuit_type, vk_commitment));
    }

    let block_aggregation_data =
        BlockAggregationOutputData::alloc_from_witness(cs, Some(block_aggregation_result))?;
    let mut oracle_aggregation_data = vec![];
    for data in oracle_aggregation_results {
        oracle_aggregation_data.push(OracleAggregationOutputData::alloc_from_witness(cs, Some(data))?);
    }
    let first_oracle_agg_data = oracle_aggregation_data[0].clone();

    let mut used_key_commitments = vec![];
    let mut inputs = vec![];
    let mut casted_aggregation_results = vec![];
    let mut aggregation_proofs = vec![block_aggregation_proof];

    let block_circuit_type = Num::alloc(cs, Some(IntoFr::<E>::into_fr(block_circuit_type as u8)))?;
    let vk_commitment_to_use = check_and_select_vk_commitment(cs, &block_vk_commitments, block_circuit_type)?;

    used_key_commitments.push(vk_commitment_to_use);
    inputs.push(commit_variable_length_encodable_item(cs, &block_aggregation_data, commit_function)?);
    casted_aggregation_results.push(block_aggregation_data.aggregation_output_data.clone());

    let mut oracle_price_commitment = Num::zero();
    let mut prices_num = Num::zero();
    let mut last_oracle_vk_hash = Num::zero();
    let mut last_oracle_input_data = OracleAggregationOutputData::empty();
    let mut used_pyth_num = Num::zero();
    for (idx, (single_oracle_data, (circuit_type, proof))) in oracle_aggregation_data.into_iter()
        .zip(oracle_aggregation_proof)
        .enumerate()
    {
        let oracle_circuit_type = Num::alloc(cs, Some(IntoFr::<E>::into_fr(circuit_type as u8)))?;
        let is_padding = Num::equals(cs, &single_oracle_data.prices_commitment.prices_commitment, &Num::zero())?;
        let temp_used_pyth_num =
            used_pyth_num.add(cs, &Num::Constant(IntoFr::<E>::into_fr(MAX_AGGREGATE_NUM)))?;
        used_pyth_num =
            Num::conditionally_select(cs, &is_padding, &used_pyth_num, &temp_used_pyth_num)?;

        if idx == 0 {
            oracle_price_commitment = single_oracle_data.prices_commitment.prices_commitment;
        } else {
            last_oracle_vk_hash.enforce_equal(cs, &single_oracle_data.oracle_vks_hash)?;
            oracle_price_commitment = {
                let offset = prices_num.mul(cs, &single_oracle_data.prices_commitment.prices_commitment)?;
                oracle_price_commitment .add(cs, &offset)?
            };
            prices_num = prices_num.add(cs, &single_oracle_data.prices_commitment.prices_num)?;
            single_oracle_data
                .guardian_set_hash
                .enforce_equal(cs, &last_oracle_input_data.guardian_set_hash)?;
            let (is_equal, is_greater) = prepacked_long_comparison(
                cs,
                &[single_oracle_data.earliest_publish_time],
                &[last_oracle_input_data.earliest_publish_time],
                &[32],
            )?;
            let is_equal_or_greater = Boolean::or(cs, &is_equal, &is_greater)?;
            Boolean::enforce_equal(cs, &is_equal_or_greater, &Boolean::constant(true))?;
        }

        aggregation_proofs.push(proof);

        let vk_commitment_to_use = check_and_select_vk_commitment(cs, &oracle_vk_commitments, oracle_circuit_type)?;

        used_key_commitments.push(vk_commitment_to_use);
        inputs.push(commit_encodable_item(cs, &single_oracle_data, commit_function)?);
        casted_aggregation_results.push(single_oracle_data.aggregation_output_data.clone());

        last_oracle_vk_hash = single_oracle_data.oracle_vks_hash;
        last_oracle_input_data = single_oracle_data;
    }

    let num_proofs_aggregated = num_proofs_aggregated_oracle + 1;
    assert_eq!(used_key_commitments.len(), inputs.len());
    assert_eq!(used_key_commitments.len(), num_proofs_aggregated);
    assert_eq!(used_key_commitments.len(), aggregation_proofs.len());
    oracle_price_commitment.enforce_equal(cs, &block_aggregation_data.final_price_commitment)?;

    // do actual work
    let [[pair_with_generator_x, pair_with_generator_y], [pair_with_x_x, pair_with_x_y]] =
        aggregate_generic_inner::<_, _, _, _, _, _, true>(
            cs,
            used_key_commitments,
            inputs,
            Some(aggregation_proofs),
            aggregation_params,
            &rns_params,
            padding_proof,
            Some(casted_aggregation_results),
            commit_function,
            Some(vks_raw_elements_witness),
            padding_vk_encoding,
            g2_elements,
            num_proofs_aggregated,
        )?;

    let vks_composition_data = VksCompositionData {
        oracle_vks_hash: first_oracle_agg_data.oracle_vks_hash,
        block_vks_root: block_aggregation_data.vk_root,
        oracle_agg_vks_commitment: enforce_commit_vks_commitments(cs, oracle_vk_commitments, commit_function)?,
        block_agg_vks_commitment: enforce_commit_vks_commitments(cs, block_vk_commitments, commit_function)?,
    };
    let vks_commitment = commit_encodable_item(cs, &vks_composition_data, commit_function)?;

    let keccak_gadget = Keccak256Gadget::new(
        cs,
        None,
        None,
        None,
        None,
        true,
        RANGE_CHECK_SINGLE_APPLICATION_TABLE_NAME,
    )?;
    let public_input_data = FinalAggregationOutputData::<E> {
        total_agg_num: Num::alloc(cs, Some(E::Fr::from_repr((num_proofs_aggregated as u64).into()).unwrap()))?,
        vks_commitment,
        blocks_commitments: block_aggregation_data.blocks_commitments,
        oracle_data: OracleOnChainData {
            used_pyth_num,
            guardian_set_index: Num::alloc(cs, Some(IntoFr::<E>::into_fr(GUARDIAN_SET_INDEX)))?,
            guardian_set_hash: first_oracle_agg_data.guardian_set_hash,
            earliest_publish_time: first_oracle_agg_data.earliest_publish_time,
        },
        aggregation_output_data: NodeAggregationOutputData {
            pair_with_x_x,
            pair_with_x_y,
            pair_with_generator_x,
            pair_with_generator_y,
        },
    };

    let bytes = public_input_data.encode_bytes(cs, &keccak_gadget)?;
    let digest = keccak_gadget.digest_from_bytes(cs, &bytes)?;
    let input_keccak_hash = keccak_output_into_bytes(cs, digest)?;

    let to_take = (E::Fr::CAPACITY as usize) / 8;
    let shifts = compute_shifts::<E::Fr>();

    let mut shift = 0;
    let mut lc = LinearCombination::zero();
    for el in input_keccak_hash.iter().rev().take(to_take) {
        lc.add_assign_number_with_coeff(&el.inner, shifts[shift]);
        shift += 8;
    }
    assert!(shift <= E::Fr::CAPACITY as usize);
    let input = lc.into_num(cs)?;

    let public_input = AllocatedNum::alloc_input(cs, || input.get_value().grab())?;
    public_input.enforce_equal(cs, &input.get_variable())?;

    Ok((public_input, public_input_data))
}

pub fn check_and_select_vk_commitment<E: Engine, CS: ConstraintSystem<E>>(
    cs: &mut CS,
    vk_commitments: &[(Num<E>, Num<E>)],
    selector: Num<E>
) -> Result<Num<E>, SynthesisError> {
    let mut vk_commitment_to_use = Num::zero();
    let mut vk_existing_flags = Vec::with_capacity(vk_commitments.len());
    for (i, (circuit_type, vk_commitment)) in vk_commitments.iter().enumerate() {
        let is_this = Num::equals(cs, circuit_type, &selector)?;
        vk_commitment_to_use = if i == 0 {
            *vk_commitment
        } else {
            Num::conditionally_select(cs, &is_this, vk_commitment, &vk_commitment_to_use)?
        };
        vk_existing_flags.push(is_this);
    }
    let existing_vk = smart_or(cs, &vk_existing_flags)?;
    can_not_be_false_if_flagged(cs, &existing_vk, &Boolean::constant(true))?;
    Ok(vk_commitment_to_use)
}
