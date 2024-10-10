use itertools::Itertools;
use rand::Rng;
use rayon::prelude::*;
use tfhe::core_crypto::algorithms::misc::*;
use tfhe::core_crypto::commons::dispersion::{DispersionParameter, Variance};
use tfhe::core_crypto::commons::noise_formulas::tuniform::lwe_programmable_bootstrap::pbs_variance_132_bits_security_tuniform;
use tfhe::integer::ciphertext::CompressedCiphertextListBuilder;
use tfhe::integer::{ClientKey, IntegerCiphertext, ServerKey};
use tfhe::shortint::parameters::list_compression::COMP_PARAM_MESSAGE_2_CARRY_2_KS_PBS_TUNIFORM_2M64;
use tfhe::shortint::parameters::*;

const NB_TESTS: usize = 30;
const NB_OPERATOR_TESTS: usize = 40;

pub fn main() {
    const NUM_BLOCKS: usize = 1;

    let compute_params = PARAM_MESSAGE_2_CARRY_2_KS_PBS_TUNIFORM_2M64;

    let cks = ClientKey::new(compute_params);
    let compute_shortint_cks: &tfhe::shortint::ClientKey = cks.as_ref();

    let radix_sks = ServerKey::new_radix_server_key(&cks);

    let comp_params = COMP_PARAM_MESSAGE_2_CARRY_2_KS_PBS_TUNIFORM_2M64;

    let private_compression_key = cks.new_compression_private_key(comp_params);

    let private_compression_glwe_sk = private_compression_key
        .clone()
        .into_raw_parts()
        .post_packing_ks_key;
    let private_compression_lwe_sk = private_compression_glwe_sk.clone().into_lwe_secret_key();

    let (compression_key, decompression_key) =
        cks.new_compression_decompression_keys(&private_compression_key);

    // To decrypt after compression
    let after_compression_shortint_cks = tfhe::shortint::ClientKey {
        glwe_secret_key: private_compression_glwe_sk.clone(),
        lwe_secret_key: private_compression_lwe_sk.clone(),
        parameters: PBSParameters::PBS(ClassicPBSParameters {
            lwe_dimension: LweDimension(1),
            glwe_dimension: GlweDimension(1),
            polynomial_size: PolynomialSize(1),
            lwe_noise_distribution: DynamicDistribution::new_t_uniform(0),
            glwe_noise_distribution: DynamicDistribution::new_t_uniform(0),
            pbs_base_log: DecompositionBaseLog(1),
            pbs_level: DecompositionLevelCount(1),
            ks_base_log: DecompositionBaseLog(1),
            ks_level: DecompositionLevelCount(1),
            message_modulus: MessageModulus(4),
            carry_modulus: CarryModulus(1),
            max_noise_level: MaxNoiseLevel::new(1),
            log2_p_fail: 0.0,
            ciphertext_modulus: CoreCiphertextModulus::new_native(),
            encryption_key_choice: EncryptionKeyChoice::Big,
        })
        .into(),
    };

    const MAX_NB_MESSAGES: usize = 4 * COMP_PARAM_MESSAGE_2_CARRY_2_KS_PBS_TUNIFORM_2M64
        .lwe_per_glwe
        .0
        / NUM_BLOCKS;

    dbg!(MAX_NB_MESSAGES);

    let mut rng = rand::thread_rng();

    let block_msg_modulus: u128 = cks.parameters().message_modulus().0 as u128;

    let mut noise_smaples = vec![];

    // The noise expected at the output of the computation PBS, the noise after decompression should
    // be below that
    let expected_variance = pbs_variance_132_bits_security_tuniform(
        compute_params.lwe_dimension,
        compute_params.glwe_dimension,
        compute_params.polynomial_size,
        compute_params.pbs_base_log,
        compute_params.pbs_level,
        2.0f64.powi(64),
    );

    for _ in 0..NB_TESTS {
        println!("Unsigned");
        // Unsigned
        let modulus = block_msg_modulus.pow(NUM_BLOCKS as u32);
        for _ in 0..NB_OPERATOR_TESTS {
            // let nb_messages = 1 + (rng.gen::<usize>() % MAX_NB_MESSAGES);
            let nb_messages = 512 / 2;
            dbg!(nb_messages);
            let messages = (0..nb_messages)
                .map(|_| rng.gen::<u128>() % modulus)
                .collect::<Vec<_>>();

            let cts = messages
                .iter()
                .map(|message| cks.encrypt_radix(*message, NUM_BLOCKS))
                .collect_vec();

            let mut builder = CompressedCiphertextListBuilder::new();

            for (idx, ct) in cts.iter().enumerate() {
                let and_ct = radix_sks.bitand_parallelized(ct, ct);
                let dec: u128 = cks.decrypt_radix(&and_ct);
                assert_eq!(dec, messages[idx]);
                builder.push(and_ct);
                // builder.push(ct.clone());
            }

            let compressed = builder.build(&compression_key);

            let tmp_samples = messages
                .par_iter()
                .enumerate()
                .map(|(i, message)| {
                    {
                        // let decompressed_shortint = compressed
                        //     .extract_mod_switched(i, &decompression_key)
                        //     .unwrap()
                        //     .0;

                        // assert_eq!(decompressed_shortint.len(), 1);

                        // let decrypted =
                        //     after_compression_shortint_cks.decrypt(&decompressed_shortint[0]) as
                        // u128; assert_eq!(decrypted, *message);

                        // let raw_plaintext =
                        //     after_compression_shortint_cks.decrypt_no_decode(&
                        // decompressed_shortint[0]); let expected_plaintext =
                        // ((1u64 << 63)     / after_compression_shortint_cks
                        //         .parameters
                        //         .message_modulus()
                        //         .0 as u64)
                        //     * (*message as u64);

                        // let torus_diff = torus_modular_diff(
                        //     expected_plaintext,
                        //     raw_plaintext,
                        //     after_compression_shortint_cks
                        //         .parameters
                        //         .ciphertext_modulus(),
                        // );

                        // println!("torus_diff={torus_diff}");
                    }

                    let decompressed = compressed.get(i, &decompression_key).unwrap().unwrap();
                    let decrypted: u128 = cks.decrypt_radix(&decompressed);
                    assert_eq!(decrypted, *message);

                    assert_eq!(decompressed.blocks().len(), 1);

                    let raw_plaintext =
                        compute_shortint_cks.decrypt_no_decode(&decompressed.blocks()[0]);
                    let expected_plaintext = ((1u64 << 63)
                        / (compute_shortint_cks.parameters.message_modulus().0
                            * compute_shortint_cks.parameters.carry_modulus().0)
                            as u64)
                        * (*message as u64);

                    let torus_diff = torus_modular_diff(
                        expected_plaintext,
                        raw_plaintext,
                        after_compression_shortint_cks
                            .parameters
                            .ciphertext_modulus(),
                    );

                    torus_diff
                })
                .collect::<Vec<_>>();

            noise_smaples.extend(tmp_samples.into_iter());
        }

        println!("With {} samples", noise_smaples.len());
        {
            println!("expected_variance={expected_variance:?}");
            let expected_std_dev = expected_variance.get_standard_dev();
            println!("expected_std_dev={expected_std_dev}");
            println!("log2_std_dev={}", expected_std_dev.log2());
        }

        {
            let measured_variance = variance(&noise_smaples);
            println!("measured_variance={measured_variance:?}");
            let measured_std_dev = measured_variance.get_standard_dev();
            println!("measured_std_dev={measured_std_dev}");
            println!("log2_std_dev={}", measured_std_dev.log2());
        }

        // println!("Signed");

        // // Signed
        // let modulus = block_msg_modulus.pow(NUM_BLOCKS as u32) as i128 / 2;
        // for _ in 0..NB_OPERATOR_TESTS {
        //     // let nb_messages = 1 + (rng.gen::<u64>() % MAX_NB_MESSAGES as u64);
        //     let nb_messages = 512 / 64;
        //     dbg!(nb_messages);
        //     let messages = (0..nb_messages)
        //         .map(|_| rng.gen::<i128>() % modulus)
        //         .collect::<Vec<_>>();

        //     // // failed and returned -7264070712496806567
        //     // .map(|_| -7264070712496836263i128)

        //     let cts = messages
        //         .iter()
        //         .map(|message| cks.encrypt_signed_radix(*message, NUM_BLOCKS))
        //         .collect_vec();

        //     let mut builder = CompressedCiphertextListBuilder::new();

        //     for (idx, ct) in cts.iter().enumerate() {
        //         let and_ct = radix_sks.bitand_parallelized(ct, ct);
        //         let dec: i128 = cks.decrypt_signed_radix(&and_ct);
        //         assert_eq!(dec, messages[idx]);
        //         builder.push(and_ct);
        //     }

        //     let compressed = builder.build(&compression_key);

        //     for (i, message) in messages.iter().enumerate() {
        //         let decompressed = compressed.get(i, &decompression_key).unwrap().unwrap();
        //         let decrypted: i128 = cks.decrypt_signed_radix(&decompressed);
        //         assert_eq!(decrypted, *message);
        //     }
        // }

        // println!("Boolean");

        // // Boolean
        // for _ in 0..NB_OPERATOR_TESTS {
        //     // let nb_messages = 1 + (rng.gen::<u64>() % MAX_NB_MESSAGES as u64);
        //     let nb_messages = 512 / 2;
        //     dbg!(nb_messages);
        //     let messages = (0..nb_messages)
        //         .map(|_| rng.gen::<u8>() % 2 != 0)
        //         .collect::<Vec<_>>();

        //     let cts = messages
        //         .iter()
        //         .map(|message| cks.encrypt_bool(*message))
        //         .collect_vec();

        //     let mut builder = CompressedCiphertextListBuilder::new();

        //     for (idx, ct) in cts.iter().enumerate() {
        //         let and_ct = radix_sks.boolean_bitand(ct, ct);
        //         let dec: bool = cks.decrypt_bool(&and_ct);
        //         assert_eq!(dec, messages[idx]);
        //         builder.push(and_ct);
        //     }

        //     let compressed = builder.build(&compression_key);

        //     for (i, message) in messages.iter().enumerate() {
        //         let decompressed = compressed.get(i, &decompression_key).unwrap().unwrap();
        //         let decrypted = cks.decrypt_bool(&decompressed);
        //         assert_eq!(decrypted, *message);
        //     }
        // }

        // println!("Hybrid");
        // // Hybrid
        // enum MessageType {
        //     Unsigned(u128),
        //     Signed(i128),
        //     Boolean(bool),
        // }

        // for _ in 0..NB_OPERATOR_TESTS {
        //     let mut builder = CompressedCiphertextListBuilder::new();

        //     let nb_messages = 1 + (rng.gen::<u64>() % MAX_NB_MESSAGES as u64);
        //     dbg!(nb_messages);
        //     let mut messages = vec![];
        //     for _ in 0..nb_messages {
        //         let case_selector = rng.gen_range(0..3);
        //         match case_selector {
        //             0 => {
        //                 // Unsigned
        //                 let modulus = message_modulus.pow(NUM_BLOCKS as u32);
        //                 let message = rng.gen::<u128>() % modulus;
        //                 let ct = cks.encrypt_radix(message, NUM_BLOCKS);
        //                 let and_ct = radix_sks.bitand_parallelized(&ct, &ct);
        //                 let dec: u128 = cks.decrypt_radix(&and_ct);
        //                 assert_eq!(dec, message);
        //                 builder.push(and_ct);
        //                 messages.push(MessageType::Unsigned(message));
        //             }
        //             1 => {
        //                 // Signed
        //                 let modulus = message_modulus.pow(NUM_BLOCKS as u32) as i128 / 2;
        //                 let message = rng.gen::<i128>() % modulus;
        //                 let ct = cks.encrypt_signed_radix(message, NUM_BLOCKS);
        //                 let and_ct = radix_sks.bitand_parallelized(&ct, &ct);
        //                 let dec: i128 = cks.decrypt_signed_radix(&and_ct);
        //                 assert_eq!(dec, message);
        //                 builder.push(and_ct);
        //                 messages.push(MessageType::Signed(message));
        //             }
        //             _ => {
        //                 // Boolean
        //                 let message = rng.gen::<i64>() % 2 != 0;
        //                 let ct = cks.encrypt_bool(message);
        //                 let and_ct = radix_sks.boolean_bitand(&ct, &ct);
        //                 let dec: bool = cks.decrypt_bool(&and_ct);
        //                 assert_eq!(dec, message);
        //                 builder.push(and_ct);
        //                 messages.push(MessageType::Boolean(message));
        //             }
        //         }
        //     }

        //     let compressed = builder.build(&compression_key);

        //     for (i, val) in messages.iter().enumerate() {
        //         match val {
        //             MessageType::Unsigned(message) => {
        //                 let decompressed = compressed.get(i,
        // &decompression_key).unwrap().unwrap();                 let decrypted: u128 =
        // cks.decrypt_radix(&decompressed);                 assert_eq!(decrypted,
        // *message);             }
        //             MessageType::Signed(message) => {
        //                 let decompressed = compressed.get(i,
        // &decompression_key).unwrap().unwrap();                 let decrypted: i128 =
        // cks.decrypt_signed_radix(&decompressed);                 assert_eq!(decrypted,
        // *message);             }
        //             MessageType::Boolean(message) => {
        //                 let decompressed = compressed.get(i,
        // &decompression_key).unwrap().unwrap();                 let decrypted =
        // cks.decrypt_bool(&decompressed);                 assert_eq!(decrypted, *message);
        //             }
        //         }
        //     }
        // }
    }
}
