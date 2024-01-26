use advanced_circuit_component::franklin_crypto::bellman::bn256::Bn256;
use advanced_circuit_component::franklin_crypto::bellman::plonk::better_better_cs::trees::binary_tree::{
    BinaryTree, BinaryTreeParams,
};
use advanced_circuit_component::franklin_crypto::bellman::plonk::better_better_cs::trees::tree_hash::BinaryTreeHasher;
use advanced_circuit_component::franklin_crypto::bellman::plonk::better_cs::cs::PlonkConstraintSystemParams as OldCSParams;
use advanced_circuit_component::franklin_crypto::bellman::plonk::better_cs::cs::PlonkCsWidth4WithNextStepParams as OldActualParams;
use advanced_circuit_component::franklin_crypto::bellman::plonk::better_cs::keys::VerificationKey;
use advanced_circuit_component::franklin_crypto::bellman::{CurveAffine, Field, ScalarEngine, SynthesisError};
use advanced_circuit_component::franklin_crypto::plonk::circuit::bigint::field::RnsParameters;
use advanced_circuit_component::franklin_crypto::plonk::circuit::verifier_circuit::data_structs::IntoLimbedWitness;
use advanced_circuit_component::franklin_crypto::rescue::RescueEngine;
use advanced_circuit_component::rescue_poseidon::GenericSponge;
use crate::params::COMMON_CRYPTO_PARAMS;
use super::witness::DefaultRescueParams;

pub struct StaticRescueBinaryTreeHasher<E: RescueEngine> {
    params: DefaultRescueParams<E>,
}

impl<E: RescueEngine> StaticRescueBinaryTreeHasher<E> {
    pub fn new(params: &DefaultRescueParams<E>) -> Self {
        Self {
            params: params.clone(),
        }
    }
}

impl<E: RescueEngine> Clone for StaticRescueBinaryTreeHasher<E> {
    fn clone(&self) -> Self {
        Self {
            params: self.params.clone(),
        }
    }
}

impl<E: RescueEngine> BinaryTreeHasher<E::Fr> for StaticRescueBinaryTreeHasher<E> {
    type Output = E::Fr;

    #[inline]
    fn placeholder_output() -> Self::Output {
        E::Fr::zero()
    }

    fn leaf_hash(&self, input: &[E::Fr]) -> Self::Output {
        GenericSponge::hash(input, &self.params, None)[0]
    }

    fn node_hash(&self, input: &[Self::Output; 2], _level: usize) -> Self::Output {
        GenericSponge::hash(input, &self.params, None)[0]
    }
}

pub fn make_vks_tree<'a, E: RescueEngine, P: OldCSParams<E>>(
    vks: &[VerificationKey<E, P>],
    params: &'a DefaultRescueParams<E>,
    rns_params: &'a RnsParameters<E, <E::G1Affine as CurveAffine>::Base>,
) -> (BinaryTree<E, StaticRescueBinaryTreeHasher<E>>, Vec<E::Fr>) {
    let mut leaf_combinations: Vec<Vec<&[E::Fr]>> = vec![vec![]; vks.len()];

    let hasher = StaticRescueBinaryTreeHasher::new(params);
    let mut vk_witnesses = vec![];

    for vk in vks.iter() {
        let witness = vk
            .into_witness_for_params(rns_params)
            .expect("must transform into limbed witness");
        vk_witnesses.push(witness);
    }

    for idx in 0..vks.len() {
        leaf_combinations[idx].push(&vk_witnesses[idx][..]);
    }

    let tree_params = BinaryTreeParams {
        values_per_leaf: VerificationKey::<E, P>::witness_size_for_params(rns_params),
    };

    let tree = BinaryTree::<E, _>::create_from_combined_leafs(
        &leaf_combinations[..],
        1,
        hasher,
        &tree_params,
    );

    let mut all_values = vec![];
    for w in vk_witnesses.into_iter() {
        all_values.extend(w);
    }

    (tree, all_values)
}

type VksTreeAndWitness = BinaryTree<Bn256, StaticRescueBinaryTreeHasher<Bn256>>;
type VksWitness = Vec<<Bn256 as ScalarEngine>::Fr>;

pub fn create_vks_tree(
    vks: &[VerificationKey<Bn256, OldActualParams>],
    tree_depth: usize,
) -> Result<(usize, (VksTreeAndWitness, VksWitness)), SynthesisError> {
    assert!(!vks.is_empty());
    let max_size = 1 << tree_depth;
    assert!(vks.len() <= max_size);

    let max_valid_idx = vks.len() - 1;

    let mut padded = vks.to_vec();
    padded.resize(max_size, vks.last().unwrap().clone());

    let (tree, witness) = make_vks_tree(
        &padded,
        &COMMON_CRYPTO_PARAMS.rescue_params,
        &COMMON_CRYPTO_PARAMS.rns_params,
    );

    Ok((max_valid_idx, (tree, witness)))
}
