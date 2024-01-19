use std::collections::BTreeMap;
use std::marker::PhantomData;
use advanced_circuit_component::recursion::node_aggregation::VK_ENCODING_LENGTH;
use advanced_circuit_component::traits::CSWitnessable;
use circuit_testing::create_vk;
use recursive_aggregation_circuit::bellman::Engine;
use crate::bellman::bn256::Bn256;
use crate::bellman::plonk::better_better_cs::cs::{Circuit, PlonkCsWidth4WithNextStepAndCustomGatesParams};
use crate::{ORACLE_CIRCUIT_TYPES_NUM, OracleAggregationCircuit, OracleOutputData, PaddingCryptoComponent, UniformProof, UniformVerificationKey};
use crate::bellman::SynthesisError;
use crate::params::COMMON_CRYPTO_PARAMS;

#[derive(Debug, Clone)]
pub struct VerificationKeyManager<C: CircuitGenerator<E>, E: Engine> {
    keys: BTreeMap<C::Params, UniformVerificationKey<Bn256>>,
    _phantom: PhantomData<C>
}

impl<C: CircuitGenerator<Bn256>> VerificationKeyManager<C, Bn256> {
    pub fn new(keys: BTreeMap<C::Params, UniformVerificationKey<Bn256>>) -> Self {
        Self { keys, _phantom: PhantomData }
    }

    pub fn from_circuit_args(args: &[C::Params]) -> Result<Self, SynthesisError> {
        let mut vk_manager = VerificationKeyManager::new(BTreeMap::new());
        for arg in args {
            let circuit = C::generate(arg);
            let key = unsafe{ std::mem::transmute(
                create_vk::<_, _, PlonkCsWidth4WithNextStepAndCustomGatesParams, false>(circuit)?
            ) };
            vk_manager.keys.insert(arg.clone(), key);
        }
        Ok(vk_manager)
    }
}

trait CircuitGenerator<E: Engine>: Circuit<E> {
    type Params: Ord + Clone;
    // type CircuitType: Circuit<E>;
    fn generate(params: &Self::Params) -> Self;
}

impl CircuitGenerator<Bn256> for OracleAggregationCircuit<'_, Bn256> {
    type Params = usize;

    fn generate(params: &Self::Params) -> Self {
        let params = *params;
        assert!(params <= 35);
        Self {
            oracle_inputs_data: vec![
                <OracleOutputData<Bn256> as CSWitnessable<Bn256>>::placeholder_witness();
                params
            ],
            proof_witnesses: vec![(0.into(), UniformProof::empty()); params],
            vks_set: (0..ORACLE_CIRCUIT_TYPES_NUM).map(|n| (n.into(), Default::default())).collect(),
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