use advanced_circuit_component::franklin_crypto::bellman::plonk::better_better_cs::gates::selector_optimized_with_d_next::SelectorOptimizedWidth4MainGateWithDNext as MainGate;
use advanced_circuit_component::recursion::aggregation::MainGateParametrizedCircuitWithNonlinearityAndLookups as MainCircuit;

mod block_aggregation;
mod crypto_utils;
mod final_aggregation;
mod key_manager;
mod oracle_aggregation;
pub mod params;

pub use advanced_circuit_component as advanced_components;
pub use advanced_circuit_component::franklin_crypto;

pub use crypto_utils::*;
pub use final_aggregation::*;
pub use oracle_aggregation::*;

pub type UniformCircuit<E> = MainCircuit<E, MainGate>;
pub type UniformProof<E> =
    franklin_crypto::bellman::plonk::better_better_cs::proof::Proof<E, UniformCircuit<E>>;
pub type UniformVerificationKey<E> =
    franklin_crypto::bellman::plonk::better_better_cs::setup::VerificationKey<E, UniformCircuit<E>>;

#[cfg(test)]
mod tests {
    use advanced_circuit_component::franklin_crypto::bellman::plonk::better_better_cs::cs::{ConstraintSystem, PlonkCsWidth4WithNextStepAndCustomGatesParams, PolyIdentifier, TrivialAssembly};
    use advanced_circuit_component::franklin_crypto::bellman::plonk::better_better_cs::gates::selector_optimized_with_d_next::SelectorOptimizedWidth4MainGateWithDNext;
    use advanced_circuit_component::franklin_crypto::bellman::plonk::better_better_cs::lookup_tables::LookupTableApplication;
    use advanced_circuit_component::testing::Bn256;
    use advanced_circuit_component::vm::tables::BitwiseLogicTable;
    use advanced_circuit_component::vm::VM_BITWISE_LOGICAL_OPS_TABLE_NAME;

    type ActualConstraintSystem = TrivialAssembly<
        Bn256,
        PlonkCsWidth4WithNextStepAndCustomGatesParams,
        SelectorOptimizedWidth4MainGateWithDNext,
    >;

    pub fn generate_test_constraint_system() -> ActualConstraintSystem {
        let (mut cs, _, _) =
            advanced_circuit_component::testing::create_test_artifacts_with_optimized_gate();
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
}
