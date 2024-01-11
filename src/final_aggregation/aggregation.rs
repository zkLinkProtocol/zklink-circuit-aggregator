use crate::bellman::plonk::better_better_cs::cs::{Gate, GateInternal};
use crate::crypto_utils::PaddingCryptoComponent;
use crate::final_aggregation::witness::{
    BlockAggregationInputData, FinalAggregationCircuitInstanceWitness, FinalAggregationInputData,
    OracleOnChainData, VksCompositionData,
};
use crate::oracle_aggregation::OracleAggregationInputData;
use crate::UniformProof;
use franklin_crypto::bellman::plonk::better_better_cs::cs::{Circuit, ConstraintSystem};
use franklin_crypto::bellman::plonk::better_better_cs::gates::selector_optimized_with_d_next::SelectorOptimizedWidth4MainGateWithDNext;
use franklin_crypto::bellman::plonk::better_better_cs::setup::VerificationKey;
use franklin_crypto::bellman::{Engine, SynthesisError};
use franklin_crypto::plonk::circuit::allocated_num::{AllocatedNum, Num};
use franklin_crypto::plonk::circuit::bigint::RnsParameters;
use franklin_crypto::plonk::circuit::boolean::Boolean;
use franklin_crypto::plonk::circuit::custom_rescue_gate::Rescue5CustomGate;
use franklin_crypto::plonk::circuit::tables::inscribe_default_range_table_for_bit_width_over_first_three_columns;
use franklin_crypto::plonk::circuit::Assignment;
use sync_vm::circuit_structures::traits::CircuitArithmeticRoundFunction;
use sync_vm::glue::optimizable_queue::{commit_encodable_item, variable_length_hash};
use sync_vm::glue::prepacked_long_comparison;
use sync_vm::project_ref;
use sync_vm::recursion::node_aggregation::{
    aggregate_generic_inner, NodeAggregationOutputData, VK_ENCODING_LENGTH,
};
use sync_vm::recursion::recursion_tree::{AggregationParameters, NUM_LIMBS};
use sync_vm::recursion::transcript::TranscriptGadget;
use sync_vm::recursion::RANGE_CHECK_TABLE_BIT_WIDTH;
use sync_vm::rescue_poseidon::HashParams;
use sync_vm::traits::{CSAllocatable, CircuitEmpty};
use sync_vm::vm::primitives::small_uints::IntoFr;

const MAX_AGGREGATE_NUM: u8 = 5 * 36;
const GUARDIAN_SET_INDEX: u8 = 3;

impl<'a, E: Engine> Circuit<E> for FinalAggregationCircuitInstanceWitness<'a, E> {
    type MainGate = SelectorOptimizedWidth4MainGateWithDNext;

    fn synthesize<CS: ConstraintSystem<E>>(&self, cs: &mut CS) -> Result<(), SynthesisError> {
        let agg_params = self.params.aggregation_params();
        let rns_params = self.params.rns_params.clone();
        let commit_hash = self.params.poseidon_hash();
        let transcript_params = &self.params.rescue_params;

        let padding = PaddingCryptoComponent::new(
            VerificationKey::empty(),
            UniformProof::empty(),
            &commit_hash,
            transcript_params,
            &rns_params,
        );
        let params = (
            1usize,
            rns_params,
            agg_params,
            padding,
            Default::default(),
            None,
        );
        let (_public_input, _input_data) = final_aggregation(cs, Some(self), &commit_hash, params)?;
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
    witness: Option<&FinalAggregationCircuitInstanceWitness<E>>,
    round_function: &R,
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
) -> Result<(AllocatedNum<E>, FinalAggregationInputData<E>), SynthesisError> {
    let (
        num_proofs_aggregated_oracle,
        rns_params,
        aggregation_params,
        PaddingCryptoComponent {
            padding_vk_commitment: _,
            padding_vk_encoding,
            padding_public_input: _,
            padding_proof,
        },
        _padding_aggregation_sets,
        g2_elements,
    ) = params;
    inscribe_default_range_table_for_bit_width_over_first_three_columns(
        cs,
        RANGE_CHECK_TABLE_BIT_WIDTH,
    )?;

    let block_aggregation_result = project_ref!(witness, block_aggregation_result).cloned();
    let oracle_aggregation_results = project_ref!(witness, oracle_aggregation_results);
    let block_aggregation_proof = project_ref!(witness, block_proof_witness).cloned();
    let oracle_aggregation_proof = project_ref!(witness, oracle_proof_witnesses).cloned();
    let oracle_vk_commitment = project_ref!(witness, oracle_vk_commitment).cloned();
    let block_vk_commitment = project_ref!(witness, block_vk_commitment).cloned();
    let block_vk_encoding_witness: Option<[E::Fr; VK_ENCODING_LENGTH]> =
        project_ref!(witness, block_vk_encoding_witness).map(|el| el.clone().try_into().unwrap());
    let oracle_vk_encoding_witness: Option<[E::Fr; VK_ENCODING_LENGTH]> =
        project_ref!(witness, oracle_vk_encoding_witness).map(|el| el.clone().try_into().unwrap());

    let block_aggregation_data =
        BlockAggregationInputData::alloc_from_witness(cs, block_aggregation_result)?;
    let mut oracle_aggregation_data = vec![];
    for oracle_agg_idx in 0..num_proofs_aggregated_oracle {
        let input_data = OracleAggregationInputData::alloc_from_witness(
            cs,
            oracle_aggregation_results.map(|res| res[oracle_agg_idx].clone()),
        )?;
        oracle_aggregation_data.push(input_data);
    }
    let first_oracle_agg_data = oracle_aggregation_data[0].clone();

    let mut used_key_commitments = vec![];
    let mut inputs = vec![];
    let mut casted_aggregation_results = vec![];
    let mut aggregation_proofs = block_aggregation_proof.map(|w| vec![w]);
    let mut vks_raw_elements_witness = block_vk_encoding_witness.map(|w| vec![w]);

    used_key_commitments.push(Num::Constant(block_vk_commitment.unwrap()));
    inputs.push(commit_encodable_item(
        cs,
        &block_aggregation_data,
        round_function,
    )?);
    casted_aggregation_results.push(block_aggregation_data.aggregation_output_data.clone());

    let mut oracle_price_commitment = Num::zero();
    let mut last_oracle_vk_hash = Num::zero();
    let mut last_oracle_input_data = OracleAggregationInputData::empty();
    let mut used_pyth_num = Num::zero();
    for (oracle_idx, single_oracle_data) in oracle_aggregation_data.into_iter().enumerate() {
        let is_padding = Num::equals(cs, &single_oracle_data.final_price_commitment, &Num::zero())?;
        let temp_used_pyth_num =
            used_pyth_num.add(cs, &Num::Constant(IntoFr::<E>::into_fr(MAX_AGGREGATE_NUM)))?;
        used_pyth_num =
            Num::conditionally_select(cs, &is_padding, &used_pyth_num, &temp_used_pyth_num)?;

        if oracle_idx == 0 {
            oracle_price_commitment = single_oracle_data.final_price_commitment;
        } else {
            last_oracle_vk_hash.enforce_equal(cs, &single_oracle_data.oracle_vks_hash)?;
            oracle_price_commitment = oracle_price_commitment
                .square(cs)?
                .add(cs, &single_oracle_data.final_price_commitment)?;
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

        if let Some(w) = vks_raw_elements_witness.as_mut() {
            w.push(oracle_vk_encoding_witness.unwrap());
        };
        if let Some(proofs) = aggregation_proofs.as_mut() {
            proofs.push(oracle_aggregation_proof.as_ref().unwrap()[oracle_idx].clone());
        }

        used_key_commitments.push(Num::Constant(oracle_vk_commitment.unwrap()));
        inputs.push(commit_encodable_item(
            cs,
            &single_oracle_data,
            round_function,
        )?);
        casted_aggregation_results.push(single_oracle_data.aggregation_output_data.clone());

        last_oracle_vk_hash = single_oracle_data.oracle_vks_hash;
        last_oracle_input_data = single_oracle_data;
    }

    let num_proofs_aggregated = num_proofs_aggregated_oracle + 1;
    assert_eq!(used_key_commitments.len(), inputs.len());
    assert_eq!(used_key_commitments.len(), num_proofs_aggregated);
    if let Some(ref proofs) = aggregation_proofs {
        assert_eq!(used_key_commitments.len(), proofs.len());
    }
    oracle_price_commitment.enforce_equal(cs, &block_aggregation_data.final_price_commitment)?;

    // do actual work
    let [[pair_with_generator_x, pair_with_generator_y], [pair_with_x_x, pair_with_x_y]] =
        aggregate_generic_inner::<_, _, _, _, _, _, true>(
            cs,
            used_key_commitments,
            inputs,
            aggregation_proofs,
            aggregation_params,
            &rns_params,
            padding_proof,
            Some(casted_aggregation_results),
            round_function,
            vks_raw_elements_witness,
            padding_vk_encoding,
            g2_elements,
            num_proofs_aggregated,
        )?;

    let vks_composition_data = VksCompositionData {
        oracle_vks_hash: block_aggregation_data.vk_root,
        block_vks_commitment: first_oracle_agg_data.oracle_vks_hash,
    };
    let vks_commitment = commit_encodable_item(cs, &vks_composition_data, round_function)?;
    let input_data = FinalAggregationInputData::<E> {
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

    let encodes = input_data.encode(cs, round_function)?;
    let input_commitment = variable_length_hash(cs, &encodes, round_function)?;
    let public_input = AllocatedNum::alloc_input(cs, || input_commitment.get_value().grab())?;
    public_input.enforce_equal(cs, &input_commitment.get_variable())?;

    Ok((public_input, input_data))
}
