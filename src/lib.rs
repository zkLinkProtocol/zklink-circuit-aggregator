use advanced_circuit_component::franklin_crypto::bellman::plonk::better_better_cs::gates::selector_optimized_with_d_next::SelectorOptimizedWidth4MainGateWithDNext as MainGate;
use advanced_circuit_component::recursion::aggregation::MainGateParametrizedCircuitWithNonlinearityAndLookups as MainCircuit;

mod crypto_utils;
mod final_aggregation;
mod oracle_aggregation;
pub mod params;

pub use advanced_circuit_component::franklin_crypto;
pub use advanced_circuit_component::franklin_crypto::bellman; // for cs_derive proc macro
pub use advanced_circuit_component as advanced_components;
pub use advanced_circuit_component::utils; // for cs_derive proc macro

pub use crypto_utils::*;
pub use final_aggregation::*;
pub use oracle_aggregation::*;

pub type UniformCircuit<E> = MainCircuit<E, MainGate>;
pub type UniformProof<E> = bellman::plonk::better_better_cs::proof::Proof<E, UniformCircuit<E>>;
pub type UniformVerificationKey<E> = bellman::plonk::better_better_cs::setup::VerificationKey<E, UniformCircuit<E>>;
