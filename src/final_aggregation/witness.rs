use std::collections::BTreeMap;
use crate::oracle_aggregation::OracleAggregationOutputDataWitness;
use crate::params::{CommonCryptoParams, COMMON_CRYPTO_PARAMS};
use crate::{final_aggregation, OracleAggregationOutputData, PaddingCryptoComponent, UniformCircuit, UniformProof, VkEncodeInfo};
use cs_derive::*;
use derivative::Derivative;
use advanced_circuit_component::franklin_crypto::bellman::plonk::better_better_cs::cs::ConstraintSystem;
use advanced_circuit_component::franklin_crypto::bellman::plonk::better_better_cs::setup::VerificationKey;
use advanced_circuit_component::franklin_crypto::bellman::{Engine, SynthesisError};
use advanced_circuit_component::franklin_crypto::plonk::circuit::allocated_num::Num;
use advanced_circuit_component::franklin_crypto::plonk::circuit::boolean::Boolean;
use advanced_circuit_component::franklin_crypto::plonk::circuit::byte::{Byte, IntoBytes};
use advanced_circuit_component::franklin_crypto::plonk::circuit::hashes_with_tables::keccak::gadgets::Keccak256Gadget;
use advanced_circuit_component::circuit_structures::traits::CircuitArithmeticRoundFunction;
use advanced_circuit_component::glue::optimizable_queue::{commit_encodable_item, commit_variable_length_encodable_item};
use advanced_circuit_component::recursion::node_aggregation::NodeAggregationOutputData;
use advanced_circuit_component::recursion::recursion_tree::NUM_LIMBS;
use advanced_circuit_component::scheduler::block_header::keccak_output_into_bytes;
use advanced_circuit_component::testing::{Bn256, create_test_artifacts};
use advanced_circuit_component::traits::*;
use advanced_circuit_component::traits::{CircuitFixedLengthEncodable, CircuitVariableLengthEncodable};
use advanced_circuit_component::vm::structural_eq::*;
use recursive_aggregation_circuit::witness::{BlockAggregationOutputData, BlockAggregationOutputDataWitness};

pub struct FinalAggregationCircuit<'a, E: Engine> {
    pub block_aggregation_result: BlockAggregationOutputDataWitness<E>,
    pub oracle_aggregation_results: Vec<OracleAggregationOutputDataWitness<E>>,

    pub oracle_proof: Vec<(usize, UniformProof<E>)>,
    pub block_proof: (usize, UniformProof<E>),

    pub oracle_vks_set: BTreeMap<usize, VkEncodeInfo<E>>,
    pub block_vks_set: BTreeMap<usize, VkEncodeInfo<E>>,

    pub output: Option<FinalAggregationOutputDataWitness<E>>,
    pub(crate) params: &'a CommonCryptoParams<E>,
}

impl FinalAggregationCircuit<'_, Bn256> {
    pub fn circuit_default(oracle_agg_num: usize, total_block_vk_type_num: usize, total_oracle_vk_type_num: usize) -> Self {
        Self {
            block_aggregation_result:
                <BlockAggregationOutputData<Bn256> as CSWitnessable<Bn256>>::placeholder_witness(),
            oracle_aggregation_results: vec![
                <OracleAggregationOutputData<Bn256> as CSWitnessable<
                    Bn256,
                >>::placeholder_witness();
                oracle_agg_num
            ],

            block_proof: (0, UniformProof::empty()),
            oracle_proof: vec![(0, UniformProof::empty()); oracle_agg_num],

            oracle_vks_set: (0..total_oracle_vk_type_num).map(|n| (n, Default::default())).collect(),
            block_vks_set: (0..total_block_vk_type_num).map(|n| (n, Default::default())).collect(),

            output: None,
            params: &COMMON_CRYPTO_PARAMS,
        }
    }

    pub fn generate(
        block_aggregation_result: BlockAggregationOutputDataWitness<Bn256>,
        block_proof: (usize, UniformProof<Bn256>),
        block_agg_vks: BTreeMap<usize, VerificationKey<Bn256, UniformCircuit<Bn256>>>,
        oracle_aggregation_results: Vec<OracleAggregationOutputDataWitness<Bn256>>,
        oracle_proof: Vec<(usize, UniformProof<Bn256>)>,
        oracle_agg_vks: BTreeMap<usize, VerificationKey<Bn256, UniformCircuit<Bn256>>>,
    ) -> Self {
        assert_eq!(
            oracle_aggregation_results.len(),
            oracle_proof.len()
        );

        let oracle_vks_commitments_set = oracle_agg_vks
            .into_iter()
            .map(|(t, vk)| (t, VkEncodeInfo::new(vk)))
            .collect();
        let block_vks_commitments_set = block_agg_vks
            .into_iter()
            .map(|(t, vk)| (t, VkEncodeInfo::new(vk)))
            .collect();

        let mut witness = Self {
            block_aggregation_result,
            oracle_aggregation_results,
            block_proof,
            oracle_proof,
            oracle_vks_set: oracle_vks_commitments_set,
            block_vks_set: block_vks_commitments_set,
            output: None,
            params: &COMMON_CRYPTO_PARAMS,
        };

        let agg_params = witness.params.aggregation_params();
        let rns_params = witness.params.rns_params.clone();
        let commit_hash = witness.params.poseidon_hash();
        let params = (
            witness.oracle_proof.len(),
            rns_params,
            agg_params,
            PaddingCryptoComponent::default(),
            Default::default(),
            None,
        );
        let (mut cs, ..) = create_test_artifacts();
        let (_public_input, public_input_data) = final_aggregation(&mut cs, &witness, &commit_hash, params)
            .expect("Failed to final aggregate");
        witness.output = public_input_data.create_witness();

        witness
    }
}

// On-chain information
#[derive(
    Derivative,
    CSAllocatable,
    CSWitnessable,
    CSVariableLengthEncodable
)]
#[derivative(Clone, Debug)]
pub struct FinalAggregationOutputData<E: Engine> {
    pub total_agg_num: Num<E>,
    pub vks_commitment: Num<E>,
    pub blocks_commitments: Vec<Num<E>>,
    pub oracle_data: OracleOnChainData<E>,
    pub aggregation_output_data: NodeAggregationOutputData<E>,
}

impl<E: Engine> FinalAggregationOutputData<E> {
    pub fn encode<
        CS: ConstraintSystem<E>,
        R: CircuitArithmeticRoundFunction<E, A_WIDTH, S_WIDTH, StateElement = Num<E>>,
        const A_WIDTH: usize,
        const S_WIDTH: usize,
    >(
        &self,
        cs: &mut CS,
        commit_function: &R,
    ) -> Result<Vec<Num<E>>, SynthesisError> {
        let mut encodes = Vec::with_capacity(3 + NUM_LIMBS * 4);
        encodes.push(self.vks_commitment);
        encodes.push(commit_variable_length_encodable_item(
            cs,
            &self.blocks_commitments,
            commit_function,
        )?);
        encodes.push(commit_encodable_item(
            cs,
            &self.oracle_data,
            commit_function,
        )?);
        encodes.extend(CircuitFixedLengthEncodable::encode(
            &self.aggregation_output_data,
            cs,
        )?);
        assert_eq!(encodes.len(), encodes.capacity());
        Ok(encodes)
    }

    pub fn encode_bytes<CS: ConstraintSystem<E>>(
        &self,
        cs: &mut CS,
        keccak_gadget: &Keccak256Gadget<E>,
    ) -> Result<Vec<Byte<E>>, SynthesisError> {
        let len = 1usize + self.blocks_commitments.len() + 1 + 4 * NUM_LIMBS;
        let mut encodes = Vec::with_capacity(len * 32);
        encodes.extend(self.vks_commitment.into_be_bytes(cs)?);

        for block_commitment  in &self.blocks_commitments {
            encodes.extend(block_commitment.into_be_bytes(cs)?);
        }

        let mut oracle_bytes = Vec::with_capacity(4 * 32);
        oracle_bytes.extend(self.oracle_data.used_pyth_num.into_be_bytes(cs)?);
        oracle_bytes.extend(self.oracle_data.guardian_set_index.into_be_bytes(cs)?);
        oracle_bytes.extend(self.oracle_data.guardian_set_hash.into_be_bytes(cs)?);
        oracle_bytes.extend(self.oracle_data.earliest_publish_time.into_be_bytes(cs)?);
        let digest = keccak_gadget.digest_from_bytes(cs, &oracle_bytes)?;
        let input_keccak_hash = keccak_output_into_bytes(cs, digest)?;
        encodes.extend(input_keccak_hash);

        for coord_limb in [
            self.aggregation_output_data.pair_with_generator_x,
            self.aggregation_output_data.pair_with_generator_y,
            self.aggregation_output_data.pair_with_x_x,
            self.aggregation_output_data.pair_with_x_y,
        ].iter().flatten() {
            encodes.extend(coord_limb.into_be_bytes(cs)?);

        }
        assert_eq!(encodes.len(), encodes.capacity());
        Ok(encodes)
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
pub struct VksCompositionData<E: Engine> {
    pub oracle_vks_hash: Num<E>,
    pub block_vks_root: Num<E>,
    pub oracle_agg_vks_commitment: Num<E>,
    pub block_agg_vks_commitment: Num<E>,
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
pub struct OracleOnChainData<E: Engine> {
    pub used_pyth_num: Num<E>,
    pub guardian_set_index: Num<E>,
    pub guardian_set_hash: Num<E>,
    pub earliest_publish_time: Num<E>,
}

// Temp: Only for block aggregation circuit
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
pub struct BlockInputData<E: Engine> {
    pub blocks_commitments: Num<E>,
    pub price_commitment: Num<E>,
}
