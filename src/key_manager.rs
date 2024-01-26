#![allow(dead_code)]
use crate::params::COMMON_CRYPTO_PARAMS;
use crate::{
    OracleAggregationCircuit, OracleOutputData, PaddingCryptoComponent, UniformProof,
    UniformVerificationKey, ORACLE_CIRCUIT_TYPES_NUM,
};
use advanced_circuit_component::circuit_structures::traits::CircuitArithmeticRoundFunction;
use advanced_circuit_component::franklin_crypto::bellman::bn256::Bn256;
use advanced_circuit_component::franklin_crypto::bellman::plonk::better_better_cs::cs::{
    Circuit, ConstraintSystem, PlonkCsWidth4WithNextStepAndCustomGatesParams,
};
use advanced_circuit_component::franklin_crypto::bellman::Engine;
use advanced_circuit_component::franklin_crypto::bellman::SynthesisError;
use advanced_circuit_component::franklin_crypto::plonk::circuit::allocated_num::Num;
use advanced_circuit_component::glue::optimizable_queue::variable_length_hash;
use advanced_circuit_component::recursion::node_aggregation::VK_ENCODING_LENGTH;
use advanced_circuit_component::traits::CSWitnessable;
use circuit_testing::create_vk;
use std::collections::BTreeMap;
use std::marker::PhantomData;

#[derive(Debug, Clone)]
pub struct VerificationKeyManager<C: CircuitGenerator<E>, E: Engine> {
    keys: BTreeMap<C::Params, UniformVerificationKey<Bn256>>,
    _phantom: PhantomData<C>,
}

impl<C: CircuitGenerator<Bn256>> VerificationKeyManager<C, Bn256> {
    pub fn new(keys: BTreeMap<C::Params, UniformVerificationKey<Bn256>>) -> Self {
        Self {
            keys,
            _phantom: PhantomData,
        }
    }

    pub fn from_circuit_args(args: &[C::Params]) -> Result<Self, SynthesisError> {
        let mut vk_manager = VerificationKeyManager::new(BTreeMap::new());
        for arg in args {
            let circuit = C::generate(arg);
            let key = unsafe {
                std::mem::transmute(create_vk::<
                    _,
                    _,
                    PlonkCsWidth4WithNextStepAndCustomGatesParams,
                    false,
                >(circuit)?)
            };
            vk_manager.keys.insert(arg.clone(), key);
        }
        Ok(vk_manager)
    }
}

pub trait CircuitGenerator<E: Engine>: Circuit<E> {
    type Params: Ord + Clone;
    fn generate(params: &Self::Params) -> Self;
}

impl CircuitGenerator<Bn256> for OracleAggregationCircuit<'_, Bn256> {
    type Params = usize;

    fn generate(params: &Self::Params) -> Self {
        let params = *params;
        Self {
            oracle_inputs_data: vec![
                <OracleOutputData<Bn256> as CSWitnessable<Bn256>>::placeholder_witness();
                params
            ],
            proof_witnesses: vec![(0.into(), UniformProof::empty()); params],
            vks_set: (0..ORACLE_CIRCUIT_TYPES_NUM)
                .map(|n| (n.into(), Default::default()))
                .collect(),
            vk_encoding_witnesses: vec![
                [Default::default(); VK_ENCODING_LENGTH];
                ORACLE_CIRCUIT_TYPES_NUM
            ],
            params: &COMMON_CRYPTO_PARAMS,
            output: None,
            padding_component: PaddingCryptoComponent::default(),
        }
    }
}

pub fn enforce_commit_vks_commitments<
    CS: ConstraintSystem<E>,
    E: Engine,
    R: CircuitArithmeticRoundFunction<E, AWIDTH, SWIDTH, StateElement = Num<E>>,
    const AWIDTH: usize,
    const SWIDTH: usize,
>(
    cs: &mut CS,
    vks_commitments: Vec<(Num<E>, Num<E>)>,
    commit_function: &R,
) -> Result<Num<E>, SynthesisError> {
    let commitments = vks_commitments
        .into_iter()
        .map(|(_, commitment)| commitment)
        .collect::<Vec<_>>();
    variable_length_hash(cs, &commitments, commit_function)
}
