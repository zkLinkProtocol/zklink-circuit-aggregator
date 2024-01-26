#![allow(dead_code)]

use advanced_circuit_component::circuit_structures::byte::IntoBytes;
use advanced_circuit_component::franklin_crypto::bellman::pairing::ff::*;
use advanced_circuit_component::franklin_crypto::bellman::pairing::*;
use advanced_circuit_component::franklin_crypto::bellman::plonk::better_better_cs::cs::*;
use advanced_circuit_component::franklin_crypto::bellman::plonk::better_better_cs::cs::Circuit;
use advanced_circuit_component::franklin_crypto::bellman::plonk::better_better_cs::gates::selector_optimized_with_d_next::SelectorOptimizedWidth4MainGateWithDNext;
use advanced_circuit_component::franklin_crypto::bellman::plonk::better_cs::cs::PlonkConstraintSystemParams as OldCSParams;
use advanced_circuit_component::franklin_crypto::bellman::plonk::better_cs::generator::make_non_residues;
use advanced_circuit_component::franklin_crypto::bellman::plonk::better_cs::keys::{Proof, VerificationKey};
use advanced_circuit_component::franklin_crypto::bellman::SynthesisError;
use advanced_circuit_component::franklin_crypto::plonk::circuit::allocated_num::*;
use advanced_circuit_component::franklin_crypto::plonk::circuit::Assignment;
use advanced_circuit_component::franklin_crypto::plonk::circuit::bigint::field::*;
use advanced_circuit_component::franklin_crypto::plonk::circuit::bigint_new::BITWISE_LOGICAL_OPS_TABLE_NAME;
use advanced_circuit_component::franklin_crypto::plonk::circuit::boolean::*;
use advanced_circuit_component::franklin_crypto::plonk::circuit::custom_rescue_gate::Rescue5CustomGate;
use advanced_circuit_component::franklin_crypto::plonk::circuit::rescue::*;
use advanced_circuit_component::franklin_crypto::plonk::circuit::tables::inscribe_default_range_table_for_bit_width_over_first_three_columns;
use advanced_circuit_component::franklin_crypto::plonk::circuit::verifier_circuit::affine_point_wrapper::aux_data::*;
use advanced_circuit_component::franklin_crypto::plonk::circuit::verifier_circuit::affine_point_wrapper::*;
use advanced_circuit_component::franklin_crypto::plonk::circuit::verifier_circuit::data_structs::*;
use advanced_circuit_component::franklin_crypto::rescue::{RescueEngine, RescueHashParams};
use advanced_circuit_component::glue::optimizable_queue::commit_variable_length_encodable_item;
use advanced_circuit_component::recursion::node_aggregation::NodeAggregationOutputData;
use advanced_circuit_component::recursion::RANGE_CHECK_TABLE_BIT_WIDTH;
use advanced_circuit_component::recursion::recursion_tree::NUM_LIMBS;
use advanced_circuit_component::recursion::transcript::TranscriptGadget;
use advanced_circuit_component::rescue_poseidon::CircuitGenericSponge;
use advanced_circuit_component::traits::GenericHasher;
use advanced_circuit_component::vm::tables::BitwiseLogicTable;
use super::DefaultPoseidonParams;

use super::witness::{BlockAggregationOutputData, BlockPublicInputData, DefaultRescueParams};

pub const ZKLINK_NUM_INPUTS: usize = 1;
pub const ALLIGN_FIELD_ELEMENTS_TO_BITS: usize = 256;

#[derive(Clone, Debug)]
pub struct RecursiveAggregationCircuit<
    'a,
    E: RescueEngine,
    P: OldCSParams<E>,
    WP: WrappedAffinePoint<'a, E>,
    AD: AuxData<E>,
    T: TranscriptGadget<E>,
> {
    pub num_proofs_to_check: usize,
    pub num_inputs: usize,
    pub vk_tree_depth: usize,
    pub vk_root: Option<E::Fr>,
    pub vk_witnesses: Option<Vec<VerificationKey<E, P>>>,
    pub vk_auth_paths: Option<Vec<Vec<E::Fr>>>,
    pub proof_ids: Option<Vec<usize>>,
    pub proofs: Option<Vec<Proof<E, P>>>,
    pub rescue_params: &'a DefaultRescueParams<E>,
    pub poseidon_params: &'a DefaultPoseidonParams<E>,
    pub rns_params: &'a RnsParameters<E, <E::G1Affine as CurveAffine>::Base>,
    pub aux_data: AD,
    pub transcript_params: &'a T::Params,
    pub public_input_data: Option<Vec<BlockPublicInputData<E>>>,
    pub g2_elements: Option<[E::G2Affine; 2]>,
    pub input_commitment: Option<E::Fr>,

    pub _m: std::marker::PhantomData<WP>,
}

impl<'a, E, P, WP, AD, T> Circuit<E> for RecursiveAggregationCircuit<'a, E, P, WP, AD, T>
where
    E: RescueEngine,
    <<E as RescueEngine>::Params as RescueHashParams<E>>::SBox0: PlonkCsSBox<E>,
    <<E as RescueEngine>::Params as RescueHashParams<E>>::SBox1: PlonkCsSBox<E>,
    P: OldCSParams<E>,
    WP: WrappedAffinePoint<'a, E>,
    AD: AuxData<E>,
    T: TranscriptGadget<E>,
{
    type MainGate = SelectorOptimizedWidth4MainGateWithDNext;

    fn synthesize<CS: ConstraintSystem<E>>(&self, cs: &mut CS) -> Result<(), SynthesisError> {
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
        inscribe_default_range_table_for_bit_width_over_first_three_columns(
            cs,
            RANGE_CHECK_TABLE_BIT_WIDTH,
        )?;

        let num_bits_in_proof_id = self.vk_tree_depth;

        let non_residues = make_non_residues::<E::Fr>(P::STATE_WIDTH - 1);

        if let Some(proofs) = self.proofs.as_ref() {
            assert_eq!(self.num_proofs_to_check, proofs.len());
        }
        if let Some(proof_ids) = self.proof_ids.as_ref() {
            assert_eq!(self.num_proofs_to_check, proof_ids.len());
        }
        if let Some(vk_witnesses) = self.vk_witnesses.as_ref() {
            assert_eq!(self.num_proofs_to_check, vk_witnesses.len());
        }
        if let Some(vk_auth_paths) = self.vk_auth_paths.as_ref() {
            assert_eq!(self.num_proofs_to_check, vk_auth_paths.len());
        }
        if let Some(public_input_data) = self.public_input_data.as_ref() {
            assert_eq!(self.num_proofs_to_check, public_input_data.len());
        }

        // Allocate everything, get fs scalar for aggregation

        let mut proof_witnesses = vec![];

        let mut fs_witnesses = vec![];

        for proof_index in 0..self.num_proofs_to_check {
            let proof_witness = self.proofs.as_ref().map(|el| el[proof_index].clone());

            if let Some(proof) = proof_witness.as_ref() {
                assert_eq!(
                    proof.input_values.len(),
                    self.num_inputs,
                    "proof has too many inputs"
                );
                // assert!(proof.input_values.len() <= self.num_inputs, "proof has too many inputs");
            }

            let allocated_proof = ProofGadget::<E, WP>::alloc_from_witness(
                cs,
                self.num_inputs,
                &proof_witness,
                self.rns_params,
                &self.aux_data,
            )?;

            let as_num_witness = allocated_proof.into_witness(cs)?;
            fs_witnesses.extend(as_num_witness);

            proof_witnesses.push(allocated_proof);
        }

        let mut vk_witnesses = vec![];

        let mut vk_leaf_witnesses = vec![];

        for proof_index in 0..self.num_proofs_to_check {
            let vk_witness = self.vk_witnesses.as_ref().map(|el| {
                el[proof_index]
                    .into_witness_for_params(self.rns_params)
                    .expect("must transform into limbed witness")
            });

            let mut allocated = vec![];

            let expected_witness_size =
                VerificationKey::<E, P>::witness_size_for_params(self.rns_params);

            if let Some(vk_witness) = vk_witness.as_ref() {
                assert_eq!(
                    vk_witness.len(),
                    expected_witness_size,
                    "witness size is not sufficient to create verification key"
                );
            }

            for idx in 0..expected_witness_size {
                let wit = vk_witness.as_ref().map(|el| el[idx]);
                let num = AllocatedNum::alloc(cs, || Ok(*wit.get()?))?;

                allocated.push(num);
            }

            let domain_size = &allocated[0];
            let omega = &allocated[1];
            let key = &allocated[2..];

            let allocated_vk = VerificationKeyGagdet::<E, WP>::alloc_from_limbs_witness::<_, P, AD>(
                cs,
                self.num_inputs,
                domain_size,
                omega,
                key,
                self.rns_params,
                non_residues.clone(),
                &self.aux_data,
            )?;

            vk_witnesses.push(allocated_vk);

            vk_leaf_witnesses.push(allocated);
        }

        // proofs and verification keys are allocated, not proceed with aggregation

        // first get that FS scalar
        let mut sponge = CircuitGenericSponge::<E, 2, 3>::new();
        for w in fs_witnesses.into_iter() {
            sponge.absorb(cs, w, self.rescue_params)?;
        }
        sponge.pad_if_necessary();
        let aggregation_challenge = sponge
            .squeeze(cs, self.rescue_params)?
            .expect("Must squeeze aggregation_challenge")
            .into_allocated_num(cs)?;

        // then perform individual aggregation

        let mut pairs_for_generator = vec![];
        let mut pairs_for_x = vec![];

        for proof_idx in 0..self.num_proofs_to_check {
            let proof = &proof_witnesses[proof_idx];
            let vk = &vk_witnesses[proof_idx];

            let [pair_with_generator, pair_with_x] =
                super::aggregation::aggregate_proof::<_, _, T, CS::Params, _, _>(
                    cs,
                    self.transcript_params,
                    &proof.input_values,
                    vk,
                    proof,
                    &self.aux_data,
                    self.rns_params,
                )?;

            pairs_for_generator.push(pair_with_generator);
            pairs_for_x.push(pair_with_x);
        }

        // now make scalars for separation

        let mut scalars = vec![];
        scalars.push(aggregation_challenge);

        let mut current = aggregation_challenge;
        for _ in 1..self.num_proofs_to_check {
            let new = current.mul(cs, &aggregation_challenge)?;
            scalars.push(new);

            current = new;
        }

        // perform final aggregation
        let pair_with_generator = WP::multiexp(
            cs,
            &scalars,
            &pairs_for_generator,
            None,
            self.rns_params,
            &self.aux_data,
        )?;
        let pair_with_x = WP::multiexp(
            cs,
            &scalars,
            &pairs_for_x,
            None,
            self.rns_params,
            &self.aux_data,
        )?;

        if let (Some(with_gen), Some(with_x), Some(g2_elements)) = (
            pair_with_generator.get_point().get_value(),
            pair_with_x.get_point().get_value(),
            self.g2_elements,
        ) {
            let valid = E::final_exponentiation(&E::miller_loop(&[
                (&with_gen.prepare(), &g2_elements[0].prepare()),
                (&with_x.prepare(), &g2_elements[1].prepare()),
            ]))
            .unwrap()
                == E::Fqk::one();

            dbg!(valid);
        }

        // check public input and compute final price commitment
        let mut final_price_commitment = Num::zero();
        let mut blocks_commitments = Vec::new();
        let mut accumulated_prices_num = Num::zero();
        for idx in 0..self.num_proofs_to_check {
            let allocated_block_commitment = {
                let value = self
                    .public_input_data
                    .as_ref()
                    .map(|el| el[idx].block_commitment);
                Num::Variable(AllocatedNum::alloc(cs, || Ok(*value.get()?))?)
            };
            let allocated_price_commitment = {
                let value = self
                    .public_input_data
                    .as_ref()
                    .map(|el| el[idx].price_commitment);
                Num::Variable(AllocatedNum::alloc(cs, || Ok(*value.get()?))?)
            };
            let allocated_prices_base_sum = {
                let value = self
                    .public_input_data
                    .as_ref()
                    .map(|el| el[idx].prices_base_sum);
                Num::Variable(AllocatedNum::alloc(cs, || Ok(*value.get()?))?)
            };
            let allocated_prices_num = {
                let value = self.public_input_data.as_ref().map(|el| el[idx].prices_num);
                Num::Variable(AllocatedNum::alloc(cs, || Ok(*value.get()?))?)
            };

            let commitment = CircuitGenericSponge::hash_num(
                cs,
                &[
                    allocated_block_commitment,
                    allocated_price_commitment,
                    allocated_prices_num,
                    allocated_prices_base_sum,
                ],
                self.poseidon_params,
                None,
            )?[0]
                .get_variable();
            let expected_input = proof_witnesses[idx].input_values[0];
            expected_input.enforce_equal(cs, &commitment)?;

            blocks_commitments.push(allocated_block_commitment);

            // Compute final price commitment
            final_price_commitment = {
                let offset = allocated_prices_base_sum.mul(cs, &accumulated_prices_num)?;
                let append = allocated_price_commitment.add(cs, &offset)?;
                final_price_commitment.add(cs, &append)?
            };
            accumulated_prices_num = accumulated_prices_num.add(cs, &allocated_prices_num)?;
        }
        // allocate vk ids

        let mut key_ids = vec![];
        let vk_root = AllocatedNum::alloc(cs, || Ok(*self.vk_root.get()?))?;

        {
            for proof_index in 0..self.num_proofs_to_check {
                let vk_witness = &vk_leaf_witnesses[proof_index];
                let path_witness = self
                    .proof_ids
                    .as_ref()
                    .map(|el| E::Fr::from_str(&el[proof_index].to_string()).unwrap());
                let path_allocated = AllocatedNum::alloc(cs, || Ok(*path_witness.get()?))?;
                key_ids.push(path_allocated);

                let path_bits = path_allocated.into_bits_le(cs, Some(num_bits_in_proof_id))?;

                let mut auth_path = vec![];
                for path_idx in 0..self.vk_tree_depth {
                    let auth_witness = self
                        .vk_auth_paths
                        .as_ref()
                        .map(|el| el[proof_index][path_idx]);
                    let auth_allocated = AllocatedNum::alloc(cs, || Ok(*auth_witness.get()?))?;

                    auth_path.push(auth_allocated);
                }

                assert_eq!(auth_path.len(), path_bits.len());

                let leaf_hash = rescue_leaf_hash(cs, vk_witness, self.rescue_params)?;

                let mut current = leaf_hash;

                for (path_bit, auth_path) in path_bits.into_iter().zip(auth_path.into_iter()) {
                    let left =
                        AllocatedNum::conditionally_select(cs, &auth_path, &current, &path_bit)?;
                    let right =
                        AllocatedNum::conditionally_select(cs, &current, &auth_path, &path_bit)?;

                    let node_hash = rescue_node_hash(cs, left, right, self.rescue_params)?;

                    current = node_hash;
                }

                current.enforce_equal(cs, &vk_root)?;
            }
        }

        let pair_with_generator = point_into_num(cs, &pair_with_generator)?;
        let pair_with_x = point_into_num(cs, &pair_with_x)?;
        assert_eq!(pair_with_generator.len(), NUM_LIMBS * 2);
        assert_eq!(pair_with_x.len(), NUM_LIMBS * 2);

        let block_aggregation_data = BlockAggregationOutputData {
            vk_root: Num::Variable(vk_root),
            final_price_commitment,
            blocks_commitments,
            aggregation_output_data: NodeAggregationOutputData {
                pair_with_x_x: pair_with_x[0..NUM_LIMBS]
                    .iter()
                    .copied()
                    .map(Num::Variable)
                    .collect::<Vec<_>>()
                    .try_into()
                    .unwrap(),
                pair_with_x_y: pair_with_x[NUM_LIMBS..]
                    .iter()
                    .copied()
                    .map(Num::Variable)
                    .collect::<Vec<_>>()
                    .try_into()
                    .unwrap(),
                pair_with_generator_x: pair_with_generator[0..NUM_LIMBS]
                    .iter()
                    .copied()
                    .map(Num::Variable)
                    .collect::<Vec<_>>()
                    .try_into()
                    .unwrap(),
                pair_with_generator_y: pair_with_generator[NUM_LIMBS..]
                    .iter()
                    .copied()
                    .map(Num::Variable)
                    .collect::<Vec<_>>()
                    .try_into()
                    .unwrap(),
            },
        };
        let commit_function = GenericHasher::new_from_params(self.poseidon_params);
        let input_commitment =
            commit_variable_length_encodable_item(cs, &block_aggregation_data, &commit_function)?;
        let expected_input_commitment =
            AllocatedNum::alloc(cs, || Ok(self.input_commitment.unwrap()))?;
        expected_input_commitment.enforce_equal(cs, &input_commitment.get_variable())?;
        expected_input_commitment.inputize(cs)?;

        input_commitment.into_be_bytes(cs)?; // only use lookup and generate commitment for final aggregation

        Ok(())
    }

    fn declare_used_gates() -> Result<Vec<Box<dyn GateInternal<E>>>, SynthesisError> {
        Ok(vec![
            SelectorOptimizedWidth4MainGateWithDNext.into_internal(),
            Rescue5CustomGate.into_internal(),
        ])
    }
}

fn allocated_num_to_alligned_big_endian<E: Engine, CS: ConstraintSystem<E>>(
    cs: &mut CS,
    el: &AllocatedNum<E>,
) -> Result<Vec<Boolean>, SynthesisError> {
    let mut bits = el.into_bits_le(cs, None)?;

    assert!(bits.len() < ALLIGN_FIELD_ELEMENTS_TO_BITS);

    bits.resize(ALLIGN_FIELD_ELEMENTS_TO_BITS, Boolean::constant(false));

    bits.reverse();

    Ok(bits)
}

fn allocated_num_to_big_endian_of_fixed_width<E: Engine, CS: ConstraintSystem<E>>(
    cs: &mut CS,
    el: &AllocatedNum<E>,
    limit: usize,
) -> Result<Vec<Boolean>, SynthesisError> {
    let mut bits = el.into_bits_le(cs, Some(limit))?;
    bits.reverse();

    Ok(bits)
}

fn serialize_point_into_big_endian<
    'a,
    E: Engine,
    CS: ConstraintSystem<E>,
    WP: WrappedAffinePoint<'a, E>,
>(
    cs: &mut CS,
    point: &WP,
) -> Result<Vec<Boolean>, SynthesisError> {
    let raw_point = point.get_point();

    let x = raw_point
        .get_x()
        .force_reduce_into_field(cs)?
        .enforce_is_normalized(cs)?;
    let y = raw_point
        .get_y()
        .force_reduce_into_field(cs)?
        .enforce_is_normalized(cs)?;

    let mut serialized = vec![];

    for coord in vec![x, y].into_iter() {
        for limb in coord.into_limbs().into_iter() {
            let as_num = limb.into_variable(); // this checks coeff and constant term internally
            serialized.extend(allocated_num_to_alligned_big_endian(cs, &as_num)?);
        }
    }

    Ok(serialized)
}

fn point_into_num<'a, E: Engine, CS: ConstraintSystem<E>, WP: WrappedAffinePoint<'a, E>>(
    cs: &mut CS,
    point: &WP,
) -> Result<Vec<AllocatedNum<E>>, SynthesisError> {
    let raw_point = point.get_point();

    let x = raw_point
        .get_x()
        .force_reduce_into_field(cs)?
        .enforce_is_normalized(cs)?;
    let y = raw_point
        .get_y()
        .force_reduce_into_field(cs)?
        .enforce_is_normalized(cs)?;

    let mut nums = vec![];
    for coord in vec![x, y].into_iter() {
        for limb in coord.into_limbs().into_iter() {
            let num = limb.into_variable(); // this checks coeff and constant term internally
            nums.push(num);
        }
    }

    Ok(nums)
}

fn rescue_leaf_hash<E: RescueEngine, CS: ConstraintSystem<E>>(
    cs: &mut CS,
    leaf: &[AllocatedNum<E>],
    params: &DefaultRescueParams<E>,
) -> Result<AllocatedNum<E>, SynthesisError> {
    let leaf = leaf.iter().copied().map(Num::Variable).collect::<Vec<_>>();
    let output = CircuitGenericSponge::hash(cs, &leaf, params, None)?[0]
        .clone()
        .into_allocated_num(cs)?;

    Ok(output)
}

fn rescue_node_hash<E: RescueEngine, CS: ConstraintSystem<E>>(
    cs: &mut CS,
    left: AllocatedNum<E>,
    right: AllocatedNum<E>,
    params: &DefaultRescueParams<E>,
) -> Result<AllocatedNum<E>, SynthesisError> {
    let output = CircuitGenericSponge::hash(
        cs,
        &[Num::Variable(left), Num::Variable(right)],
        params,
        None,
    )?[0]
        .clone()
        .into_allocated_num(cs)?;

    Ok(output)
}
