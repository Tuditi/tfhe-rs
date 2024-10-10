use tfhe_versionable::Versionize;

use crate::core_crypto::prelude::{CiphertextModulusLog, LweCiphertextCount, StandardDev};
use crate::shortint::backward_compatibility::parameters::list_compression::CompressionParametersVersions;
use crate::shortint::parameters::{
    DecompositionBaseLog, DecompositionLevelCount, DynamicDistribution, GlweDimension,
    PolynomialSize,
};
use std::fmt::Debug;

#[derive(Copy, Clone, Debug, PartialEq, serde::Serialize, serde::Deserialize, Versionize)]
#[versionize(CompressionParametersVersions)]
pub struct CompressionParameters {
    pub br_level: DecompositionLevelCount,
    pub br_base_log: DecompositionBaseLog,
    pub packing_ks_level: DecompositionLevelCount,
    pub packing_ks_base_log: DecompositionBaseLog,
    pub packing_ks_polynomial_size: PolynomialSize,
    pub packing_ks_glwe_dimension: GlweDimension,
    pub lwe_per_glwe: LweCiphertextCount,
    pub storage_log_modulus: CiphertextModulusLog,
    pub packing_ks_key_noise_distribution: DynamicDistribution<u64>,
}

// 512    2    0.000     25.000    221.81    1.64e-20    NOPRE    NOPOST    NOREFR    {'b_ks_pks':
// 16,    'b_bs_pks':    8388608,    'l_ks_pks':     4,    'l_bs_pks':    1,    'k_pks':    4,
// 'N_pks':    256,    'N_stg':    1024}

pub const COMP_PARAM_MESSAGE_2_CARRY_2_KS_PBS_TUNIFORM_2M64: CompressionParameters =
    CompressionParameters {
        br_level: DecompositionLevelCount(1),
        br_base_log: DecompositionBaseLog(25),
        packing_ks_level: DecompositionLevelCount(2),
        packing_ks_base_log: DecompositionBaseLog(8),
        packing_ks_polynomial_size: PolynomialSize(256),
        packing_ks_glwe_dimension: GlweDimension(5),
        lwe_per_glwe: LweCiphertextCount(256),
        storage_log_modulus: CiphertextModulusLog(12),
        packing_ks_key_noise_distribution: DynamicDistribution::new_t_uniform(36),
    };

// pub const COMP_PARAM_MESSAGE_2_CARRY_2_KS_PBS_TUNIFORM_2M64: CompressionParameters =
//     CompressionParameters {
//         br_level: DecompositionLevelCount(1),
//         br_base_log: DecompositionBaseLog(23),
//         packing_ks_level: DecompositionLevelCount(4),
//         packing_ks_base_log: DecompositionBaseLog(4),
//         packing_ks_polynomial_size: PolynomialSize(256),
//         packing_ks_glwe_dimension: GlweDimension(4),
//         lwe_per_glwe: LweCiphertextCount(256),
//         storage_log_modulus: CiphertextModulusLog(12),
//         packing_ks_key_noise_distribution: DynamicDistribution::new_t_uniform(42),
//     };

pub const COMP_PARAM_MESSAGE_2_CARRY_2_KS_PBS_GAUSSIAN_2M64: CompressionParameters =
    CompressionParameters {
        br_level: DecompositionLevelCount(1),
        br_base_log: DecompositionBaseLog(25),
        packing_ks_level: DecompositionLevelCount(2),
        packing_ks_base_log: DecompositionBaseLog(8),
        packing_ks_polynomial_size: PolynomialSize(256),
        packing_ks_glwe_dimension: GlweDimension(5),
        lwe_per_glwe: LweCiphertextCount(256),
        storage_log_modulus: CiphertextModulusLog(11),
        packing_ks_key_noise_distribution: DynamicDistribution::new_gaussian_from_std_dev(
            StandardDev(1.6173527465097522e-09),
        ),
    };
