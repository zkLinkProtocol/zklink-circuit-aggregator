use advanced_circuit_component::franklin_crypto::bellman::bn256::Bn256;
use advanced_circuit_component::franklin_crypto::bellman::Engine;
use advanced_circuit_component::franklin_crypto::plonk::circuit::bigint::RnsParameters;
use advanced_circuit_component::recursion::recursion_tree::AggregationParameters;
use advanced_circuit_component::recursion::transcript::{
    GenericTranscriptForRNSInFieldOnly, GenericTranscriptGadget,
};
use advanced_circuit_component::recursion::{
    get_base_placeholder_point_for_accumulators, get_prefered_rns_params,
};
use advanced_circuit_component::rescue_poseidon::{PoseidonParams, RescueParams};
use advanced_circuit_component::traits::GenericHasher;
use advanced_circuit_component::utils::bn254_rescue_params;
use once_cell::sync::Lazy;

pub const RATE: usize = 2;
pub const WIDTH: usize = 3;
pub type RescueTranscriptForRecursion<'a, E> =
    GenericTranscriptForRNSInFieldOnly<'a, E, DefaultRescueParams<E>, RATE, WIDTH>;
pub type DefaultRescueParams<E> = RescueParams<E, RATE, WIDTH>;
pub type DefaultPoseidonParams<E> = PoseidonParams<E, RATE, WIDTH>;
pub type RescueHash<E> = GenericHasher<E, RescueParams<E, RATE, WIDTH>, RATE, WIDTH>;
pub type PoseidonHash<E> = GenericHasher<E, PoseidonParams<E, RATE, WIDTH>, RATE, WIDTH>;
pub type DefaultTranscriptGadget<E> =
    GenericTranscriptGadget<E, DefaultRescueParams<E>, RATE, WIDTH>;

#[derive(Debug, Clone)]
pub struct CommonCryptoParams<E: Engine> {
    pub base_placeholder_point: E::G1Affine,
    pub poseidon_params: PoseidonParams<E, 2, 3>,
    pub rescue_params: RescueParams<E, 2, 3>,
    pub rns_params: RnsParameters<E, E::Fq>,
}

impl<E: Engine> CommonCryptoParams<E> {
    pub fn aggregation_params(
        &self,
    ) -> AggregationParameters<E, DefaultTranscriptGadget<E>, DefaultRescueParams<E>, 2, 3> {
        AggregationParameters::<_, GenericTranscriptGadget<_, _, 2, 3>, _, 2, 3> {
            base_placeholder_point: self.base_placeholder_point,
            transcript_params: self.rescue_params.clone(),
            hash_params: self.rescue_params.clone(),
        }
    }

    pub fn poseidon_hash(&self) -> PoseidonHash<E> {
        GenericHasher::new_from_params(&self.poseidon_params)
    }

    pub fn rescue_hash(&self) -> RescueHash<E> {
        GenericHasher::new_from_params(&self.rescue_params)
    }

    pub fn recursive_transcript_params(
        &self,
    ) -> (&DefaultRescueParams<E>, &RnsParameters<E, E::Fq>) {
        (&self.rescue_params, &self.rns_params)
    }
}

pub static COMMON_CRYPTO_PARAMS: Lazy<CommonCryptoParams<Bn256>> = Lazy::new(|| {
    let poseidon_params = PoseidonParams::default();
    let rns_params = get_prefered_rns_params();
    let rescue_params = bn254_rescue_params();

    CommonCryptoParams {
        base_placeholder_point: get_base_placeholder_point_for_accumulators(),
        poseidon_params,
        rescue_params,
        rns_params,
    }
});
