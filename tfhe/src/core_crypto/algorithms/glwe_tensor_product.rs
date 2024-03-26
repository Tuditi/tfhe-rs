use crate::core_crypto::algorithms::polynomial_algorithms::*;
use crate::core_crypto::commons::traits::*;
use crate::core_crypto::entities::*;
use crate::core_crypto::prelude::*;
//use crate::core_crypto::commons::math::random::Serialize;
use crate::core_crypto::fft_impl::fft64::math::fft::{FftView};
use crate::core_crypto::fft_impl::fft64::crypto::bootstrap::{
    FourierLweBootstrapKey,
};
use concrete_fft::c64;

/// Compute the tensor product of the left-hand side [`GLWE ciphertext`](`GlweCiphertext`) with the
/// right-hand side [`GLWE ciphertext`](`GlweCiphertext`)
/// writing the result in the output [`GlweCiphertext<Vec<Scalar>>`](`GlweCiphertext<Vec<Scalar>>`).
///
/// # Example
///
/// ```
/// use tfhe::core_crypto::algorithms::polynomial_algorithms::*;
/// use tfhe::core_crypto::prelude::*;
///
/// // DISCLAIMER: these toy example parameters are not guaranteed to be secure or yield correct
/// // computations
/// // Define parameters for LweCiphertext creation
/// let glwe_size = GlweSize(3);
/// let polynomial_size = PolynomialSize(512);
/// let glwe_modular_std_dev = StandardDev(0.000000000000000000029403601535432533);
/// let decomp_base_log = DecompositionBaseLog(3);
/// let decomp_level_count = DecompositionLevelCount(7);
/// let ciphertext_modulus = CiphertextModulus::new_native();
///
/// let log_delta1 = 59;
/// let log_delta2 = 60;
/// let log_delta = std::cmp::min(log_delta1, log_delta2);
/// let output_log_delta = log_delta1 + log_delta2 - log_delta;
///
/// // Create the PRNG
/// let mut seeder = new_seeder();
/// let seeder = seeder.as_mut();
/// let mut encryption_generator =
///     EncryptionRandomGenerator::<ActivatedRandomGenerator>::new(seeder.seed(), seeder);
/// let mut secret_generator =
///     SecretRandomGenerator::<ActivatedRandomGenerator>::new(seeder.seed());
///
/// // Create the GlweSecretKey
/// let glwe_secret_key = allocate_and_generate_new_binary_glwe_secret_key(
///     glwe_size.to_glwe_dimension(),
///     polynomial_size,
///     &mut secret_generator,
/// );
///
/// // Create the first plaintext, we encrypt a single integer rather than a general polynomial
/// let msg_1 = 3u64;
/// let encoded_msg_1 = msg_1 << log_delta1;
///
/// let mut plaintext_list_1 = PlaintextList::new(0u64, PlaintextCount(polynomial_size.0));
/// plaintext_list_1.as_mut()[0] = encoded_msg_1;
///
/// // Create the first GlweCiphertext
/// let mut glwe_1 = GlweCiphertext::new(0u64, glwe_size, polynomial_size, ciphertext_modulus);
///
/// encrypt_glwe_ciphertext(
///     &glwe_secret_key,
///     &mut glwe_1,
///     &plaintext_list_1,
///     glwe_modular_std_dev,
///     &mut encryption_generator,
/// );
///
/// // Create the second plaintext
/// let msg_2 = 2u64;
/// let encoded_msg_2 = msg_2 << log_delta2;
///
/// let mut plaintext_list_2 = PlaintextList::new(0u64, PlaintextCount(polynomial_size.0));
/// plaintext_list_2.as_mut()[0] = encoded_msg_2;
///
/// // Create the second GlweCiphertext
/// let mut glwe_2 = GlweCiphertext::new(0u64, glwe_size, polynomial_size, ciphertext_modulus);
///
/// encrypt_glwe_ciphertext(
///     &glwe_secret_key,
///     &mut glwe_2,
///     &plaintext_list_2,
///     glwe_modular_std_dev,
///     &mut encryption_generator,
/// );
///
/// // Perform the tensor product
/// let scale = 1u64 << log_delta;
/// let tensor_output = glwe_tensor_product(&glwe_1, &glwe_2, scale);
///
/// // Compute the tensor product key
/// let tensor_glwe_dim = GlweDimension((glwe_size.0 - 1) * (glwe_size.0 + 2) / 2);
/// let mut tensor_key_poly_list =
///     PolynomialList::new(0u64, polynomial_size, PolynomialCount(tensor_glwe_dim.0));
/// let mut key_iter = tensor_key_poly_list.iter_mut();
///
/// for i in 0..glwe_size.0 - 1 {
///     for j in 0..i + 1 {
///         let mut key_pol = key_iter.next().unwrap();
///         polynomial_wrapping_sub_mul_assign(
///             &mut key_pol,
///             &glwe_secret_key.as_polynomial_list().get(i),
///             &glwe_secret_key.as_polynomial_list().get(j),
///         );
///     }
///     let mut key_pol = key_iter.next().unwrap();
///     polynomial_wrapping_add_assign(&mut key_pol, &glwe_secret_key.as_polynomial_list().get(i));
/// }
///
/// let tensor_key = GlweSecretKey::from_container(tensor_key_poly_list.as_ref(), polynomial_size);
///
/// // Decrypt the tensor product ciphertext
/// let mut output_plaintext = PlaintextList::new(0u64, PlaintextCount(polynomial_size.0));
///
/// // First create a decomposer working on the high 4 bits corresponding to our encoding.
/// let decomposer = SignedDecomposer::new(DecompositionBaseLog(2), DecompositionLevelCount(4));
///
/// decrypt_glwe_ciphertext(&tensor_key, &tensor_output, &mut output_plaintext);
/// output_plaintext
///     .iter_mut()
///     .for_each(|elt| *elt.0 = decomposer.closest_representable(*elt.0));
///
/// // Get the raw vector
/// let mut cleartext = output_plaintext.into_container();
/// // Remove the encoding
/// cleartext
///     .iter_mut()
///     .for_each(|elt| *elt = *elt >> output_log_delta);
/// // Get the list immutably
/// let cleartext = cleartext;
///
/// // Compute what the product should be
/// let pt1 = Polynomial::from_container(
///     plaintext_list_1
///         .into_container()
///         .iter()
///         .map(|&x| <u64 as CastInto<u128>>::cast_into(x))
///         .collect::<Vec<_>>(),
/// );
/// let pt2 = Polynomial::from_container(
///     plaintext_list_2
///         .into_container()
///         .iter()
///         .map(|&x| <u64 as CastInto<u128>>::cast_into(x))
///         .collect::<Vec<_>>(),
/// );
///
/// let mut product = Polynomial::new(0u128, polynomial_size);
/// polynomial_wrapping_mul(&mut product, &pt1, &pt2);
///
/// let mut scaled_product = Polynomial::new(0u64, polynomial_size);
/// scaled_product
///     .as_mut()
///     .iter_mut()
///     .zip(product.as_ref().iter())
///     .for_each(|(dest, &source)| {
///         *dest = u64::cast_from(source / <u64 as CastInto<u128>>::cast_into(scale))
///             >> output_log_delta
///     });
///
/// // Check we recovered the correct message
/// cleartext
///     .iter()
///     .zip(scaled_product.iter())
///     .for_each(|(&elt, coeff)| assert_eq!(elt, *coeff));
///
/// let glwe_relin_key = allocate_and_generate_glwe_relinearisation_key(
///     &glwe_secret_key,
///     decomp_base_log,
///     decomp_level_count,
///     glwe_modular_std_dev,
///     ciphertext_modulus,
///     &mut encryption_generator,
/// );
///
/// let mut output_glwe_ciphertext =
///     GlweCiphertext::new(0u64, glwe_size, polynomial_size, ciphertext_modulus);
///
/// glwe_relinearisation(&tensor_output, &glwe_relin_key, &mut output_glwe_ciphertext);
///
/// // Decrypt the output glwe ciphertext
/// let mut output_plaintext = PlaintextList::new(0u64, PlaintextCount(polynomial_size.0));
///
/// decrypt_glwe_ciphertext(
///     &glwe_secret_key,
///     &output_glwe_ciphertext,
///     &mut output_plaintext,
/// );
/// output_plaintext
///     .iter_mut()
///     .for_each(|elt| *elt.0 = decomposer.closest_representable(*elt.0));
///
/// // Get the raw vector
/// let mut cleartext = output_plaintext.into_container();
/// // Remove the encoding
/// cleartext
///     .iter_mut()
///     .for_each(|elt| *elt = *elt >> output_log_delta);
/// // Get the list immutably
/// let cleartext = cleartext;
///
/// // Check we recovered the correct message
/// cleartext
///     .iter()
///     .zip(scaled_product.iter())
///     .for_each(|(&elt, coeff)| assert_eq!(elt, *coeff));
/// ```
/// based on algorithm 1 of `<https://eprint.iacr.org/2021/729.pdf>` in the eprint paper the result
/// of the division is rounded,
/// here the division in u128 performs a floor hence the induced error might be twice as large
pub fn glwe_tensor_product<InputCont, Scalar>(
    input_glwe_ciphertext_lhs: &GlweCiphertext<InputCont>,
    input_glwe_ciphertext_rhs: &GlweCiphertext<InputCont>,
    scale: Scalar,
) -> GlweCiphertext<Vec<Scalar>>
where
    Scalar: UnsignedTorus + CastInto<u128> + CastFrom<u128>,
    InputCont: Container<Element = Scalar>,
{
    assert!(
        input_glwe_ciphertext_lhs.polynomial_size().0
            == input_glwe_ciphertext_rhs.polynomial_size().0,
        "The input glwe ciphertexts do not have the same polynomial size. The polynomial size of \
        the lhs is {}, while for the rhs it is {}.",
        input_glwe_ciphertext_lhs.polynomial_size().0,
        input_glwe_ciphertext_rhs.polynomial_size().0
    );

    assert!(
        input_glwe_ciphertext_lhs.glwe_size().0 == input_glwe_ciphertext_rhs.glwe_size().0,
        "The input glwe ciphertexts do not have the same glwe size. The glwe size of the lhs is \
        {}, while for the rhs it is {}.",
        input_glwe_ciphertext_lhs.glwe_size().0,
        input_glwe_ciphertext_rhs.glwe_size().0
    );

    assert_eq!(
        input_glwe_ciphertext_lhs.ciphertext_modulus(),
        input_glwe_ciphertext_rhs.ciphertext_modulus()
    );

    let k = input_glwe_ciphertext_lhs.glwe_size().to_glwe_dimension().0;

    // This is k + k*(k-1)/2 + k: k square terms, k*(k-1)/2 cross terms, k linear terms
    let new_k = GlweDimension(k * (k + 3) / 2);

    let mut output_glwe_ciphertext = GlweCiphertextOwned::new(
        Scalar::ZERO,
        new_k.to_glwe_size(),
        input_glwe_ciphertext_lhs.polynomial_size(),
        input_glwe_ciphertext_lhs.ciphertext_modulus(),
    );

    let mut output_mask = output_glwe_ciphertext.get_mut_mask();
    let mut output_mask_poly_list = output_mask.as_mut_polynomial_list();
    let mut iter_output_mask = output_mask_poly_list.iter_mut();
    let input_lhs = PolynomialList::from_container(
        input_glwe_ciphertext_lhs
            .get_mask()
            .as_ref()
            .iter()
            .map(|&x| <Scalar as CastInto<u128>>::cast_into(x))
            .collect::<Vec<_>>(),
        input_glwe_ciphertext_lhs.polynomial_size(),
    );
    let input_rhs = PolynomialList::from_container(
        input_glwe_ciphertext_rhs
            .get_mask()
            .as_ref()
            .iter()
            .map(|&x| <Scalar as CastInto<u128>>::cast_into(x))
            .collect::<Vec<_>>(),
        input_glwe_ciphertext_rhs.polynomial_size(),
    );

    for (i, a_lhs_i) in input_lhs.iter().enumerate() {
        for (j, a_rhs_j) in input_rhs.iter().enumerate() {
            if i == j {
                //tensor elements corresponding to key -s_i^2
                let mut temp_poly_sq = Polynomial::new(0u128, a_lhs_i.polynomial_size());
                polynomial_wrapping_add_mul_assign(&mut temp_poly_sq, &a_lhs_i, &a_rhs_j);

                let mut output_poly_sq = iter_output_mask.next().unwrap();
                output_poly_sq
                    .as_mut()
                    .iter_mut()
                    .zip(temp_poly_sq.as_ref().iter())
                    .for_each(|(dest, &source)| {
                        *dest =
                            Scalar::cast_from(source / <Scalar as CastInto<u128>>::cast_into(scale))
                    });

                //tensor elements corresponding to key s_i
                let mut temp_poly_s1 = Polynomial::new(0u128, a_lhs_i.polynomial_size());
                polynomial_wrapping_add_mul_assign(
                    &mut temp_poly_s1,
                    &a_lhs_i,
                    &Polynomial::from_container(
                        input_glwe_ciphertext_rhs
                            .get_body()
                            .as_ref()
                            .iter()
                            .map(|&x| <Scalar as CastInto<u128>>::cast_into(x))
                            .collect::<Vec<_>>(),
                    ),
                );

                let mut temp_poly_s2 = Polynomial::new(0u128, a_lhs_i.polynomial_size());
                polynomial_wrapping_add_mul_assign(
                    &mut temp_poly_s2,
                    &Polynomial::from_container(
                        input_glwe_ciphertext_lhs
                            .get_body()
                            .as_ref()
                            .iter()
                            .map(|&x| <Scalar as CastInto<u128>>::cast_into(x))
                            .collect::<Vec<_>>(),
                    ),
                    &a_rhs_j,
                );

                polynomial_wrapping_add_assign(&mut temp_poly_s1, &temp_poly_s2);
                let mut output_poly_s = iter_output_mask.next().unwrap();
                output_poly_s
                    .as_mut()
                    .iter_mut()
                    .zip(temp_poly_s1.as_ref().iter())
                    .for_each(|(dest, &source)| {
                        *dest =
                            Scalar::cast_from(source / <Scalar as CastInto<u128>>::cast_into(scale))
                    });
            } else {
                //when i and j are different we only compute the terms where j < i
                if j < i {
                    //tensor element corresponding to key -s_i*s_j
                    let mut temp_poly = Polynomial::new(0u128, a_lhs_i.polynomial_size());
                    polynomial_wrapping_add_mul_assign(&mut temp_poly, &a_lhs_i, &a_rhs_j);
                    polynomial_wrapping_add_mul_assign(
                        &mut temp_poly,
                        &input_lhs.get(j),
                        &input_rhs.get(i),
                    );

                    let mut output_poly = iter_output_mask.next().unwrap();
                    output_poly
                        .as_mut()
                        .iter_mut()
                        .zip(temp_poly.as_ref().iter())
                        .for_each(|(dest, &source)| {
                            *dest = Scalar::cast_from(
                                source / <Scalar as CastInto<u128>>::cast_into(scale),
                            )
                        });
                }
            }
        }
    }

    //tensor element corresponding to the body
    let mut temp_poly_body = Polynomial::new(0u128, input_glwe_ciphertext_lhs.polynomial_size());
    polynomial_wrapping_add_mul_assign(
        &mut temp_poly_body,
        &Polynomial::from_container(
            input_glwe_ciphertext_lhs
                .get_body()
                .as_ref()
                .iter()
                .map(|&x| <Scalar as CastInto<u128>>::cast_into(x))
                .collect::<Vec<_>>(),
        ),
        &Polynomial::from_container(
            input_glwe_ciphertext_rhs
                .get_body()
                .as_ref()
                .iter()
                .map(|&x| <Scalar as CastInto<u128>>::cast_into(x))
                .collect::<Vec<_>>(),
        ),
    );
    let mut output_body = output_glwe_ciphertext.get_mut_body();
    let mut output_poly_body = output_body.as_mut_polynomial();
    output_poly_body
        .as_mut()
        .iter_mut()
        .zip(temp_poly_body.as_ref().iter())
        .for_each(|(dest, &source)| {
            *dest = Scalar::cast_from(source / <Scalar as CastInto<u128>>::cast_into(scale))
        });
    output_glwe_ciphertext
}

/// Relinearise the [`GLWE ciphertext`](`GlweCiphertext`) that is output by the
/// glwe_tensor_product operation using a [`GLWE relinearisation key`](`GlweRelinearisationKey`).
pub fn glwe_relinearisation<InputCont, KeyCont, OutputCont, Scalar>(
    input_glwe_ciphertext: &GlweCiphertext<InputCont>,
    relinearisation_key: &GlweRelinearisationKey<KeyCont>,
    output_glwe_ciphertext: &mut GlweCiphertext<OutputCont>,
) where
    Scalar: UnsignedTorus,
    InputCont: Container<Element = Scalar>,
    KeyCont: Container<Element = Scalar>,
    OutputCont: ContainerMut<Element = Scalar>,
{
    //assume input and output have same dimensions
    assert_eq!(
        relinearisation_key.glwe_dimension().0 * (relinearisation_key.glwe_dimension().0 + 3) / 2,
        input_glwe_ciphertext.glwe_size().to_glwe_dimension().0
    );
    assert_eq!(
        relinearisation_key.glwe_size(),
        output_glwe_ciphertext.glwe_size()
    );
    assert_eq!(
        relinearisation_key.polynomial_size(),
        input_glwe_ciphertext.polynomial_size()
    );
    assert_eq!(
        relinearisation_key.polynomial_size(),
        output_glwe_ciphertext.polynomial_size()
    );

    // Clear the output ciphertext, as it will get updated gradually
    output_glwe_ciphertext.as_mut().fill(Scalar::ZERO);

    // Copy the input body to the output ciphertext
    polynomial_wrapping_add_assign(
        &mut output_glwe_ciphertext.get_mut_body().as_mut_polynomial(),
        &input_glwe_ciphertext.get_body().as_polynomial(),
    );

    // We instantiate a decomposer
    let decomposer = SignedDecomposer::new(
        relinearisation_key.decomposition_base_log(),
        relinearisation_key.decomposition_level_count(),
    );

    let mut relin_key_iter = relinearisation_key.iter();
    let input_glwe_mask = input_glwe_ciphertext.get_mask();
    let input_glwe_mask_poly_list = input_glwe_mask.as_polynomial_list();
    let mut input_poly_iter = input_glwe_mask_poly_list.iter();

    for i in 0..relinearisation_key.glwe_size().0 - 1 {
        for _ in 0..i + 1 {
            let ksk = relin_key_iter.next().unwrap();
            let pol = input_poly_iter.next().unwrap();
            let mut decomposition_iter = decomposer.decompose_slice(pol.as_ref());
            // loop over the number of levels in reverse (from highest to lowest)
            for level_key_ciphertext in ksk.iter().rev() {
                let decomposed = decomposition_iter.next_term().unwrap();
                polynomial_list_wrapping_sub_scalar_mul_assign(
                    &mut output_glwe_ciphertext.as_mut_polynomial_list(),
                    &level_key_ciphertext.as_polynomial_list(),
                    &Polynomial::from_container(decomposed.as_slice()),
                );
            }
        }
        let pol = input_poly_iter.next().unwrap();
        polynomial_wrapping_add_assign(
            &mut output_glwe_ciphertext.as_mut_polynomial_list().get_mut(i),
            &pol,
        )
    }
}

/// # Example
///
/// ```
/// use tfhe::core_crypto::algorithms::polynomial_algorithms::*;
/// use tfhe::core_crypto::prelude::*;
///
/// // DISCLAIMER: these toy example parameters are not guaranteed to be secure or yield correct
/// // computations
/// // Define parameters for LweCiphertext creation
/// let glwe_size = GlweSize(3);
/// let polynomial_size = PolynomialSize(1024);
/// let glwe_modular_std_dev = StandardDev(0.000000000000000315293223915005);
/// let decomp_base_log = DecompositionBaseLog(23);
/// let decomp_level_count = DecompositionLevelCount(1);
/// let ciphertext_modulus = CiphertextModulus::new_native();
///
/// let log_delta1 = 59;
/// let log_delta2 = 59;
/// let log_delta = std::cmp::min(log_delta1, log_delta2);
/// let output_log_delta = log_delta1 + log_delta2 - log_delta;
///
/// // Create the PRNG
/// let mut seeder = new_seeder();
/// let seeder = seeder.as_mut();
/// let mut encryption_generator =
///     EncryptionRandomGenerator::<ActivatedRandomGenerator>::new(seeder.seed(), seeder);
/// let mut secret_generator =
///     SecretRandomGenerator::<ActivatedRandomGenerator>::new(seeder.seed());
///
/// // Create the GlweSecretKey
/// let glwe_secret_key = allocate_and_generate_new_binary_glwe_secret_key(
///     glwe_size.to_glwe_dimension(),
///     polynomial_size,
///     &mut secret_generator,
/// );
///
/// // Create the first plaintext, we encrypt a single integer rather than a general polynomial
/// let msg_1 = 3u64;
/// let encoded_msg_1 = msg_1 << log_delta1;
///
/// let mut plaintext_list_1 = PlaintextList::new(0u64, PlaintextCount(polynomial_size.0));
/// plaintext_list_1.as_mut()[0] = encoded_msg_1;
///
/// // Create the first GlweCiphertext
/// let mut glwe_1 = GlweCiphertext::new(0u64, glwe_size, polynomial_size, ciphertext_modulus);
///
/// encrypt_glwe_ciphertext(
///     &glwe_secret_key,
///     &mut glwe_1,
///     &plaintext_list_1,
///     glwe_modular_std_dev,
///     &mut encryption_generator,
/// );
///
/// // Create the second plaintext
/// let msg_2 = 2u64;
/// let encoded_msg_2 = msg_2 << log_delta2;
///
/// let mut plaintext_list_2 = PlaintextList::new(0u64, PlaintextCount(polynomial_size.0));
/// plaintext_list_2.as_mut()[0] = encoded_msg_2;
///
/// // Create the second GlweCiphertext
/// let mut glwe_2 = GlweCiphertext::new(0u64, glwe_size, polynomial_size, ciphertext_modulus);
///
/// encrypt_glwe_ciphertext(
///     &glwe_secret_key,
///     &mut glwe_2,
///     &plaintext_list_2,
///     glwe_modular_std_dev,
///     &mut encryption_generator,
/// );
///
/// // Perform the tensor product
/// let scale = 1u64 << log_delta;
///
/// let glwe_relin_key = allocate_and_generate_glwe_relinearisation_key(
///     &glwe_secret_key,
///     decomp_base_log,
///     decomp_level_count,
///     glwe_modular_std_dev,
///     ciphertext_modulus,
///     &mut encryption_generator,
/// );
///
/// let mut output_glwe_ciphertext =
///     GlweCiphertext::new(0u64, glwe_size, polynomial_size, ciphertext_modulus);
///
/// tensor_mult_with_relin(&glwe_1, &glwe_2, scale, &glwe_relin_key, &mut output_glwe_ciphertext);
///
/// // Decrypt the output glwe ciphertext
/// let mut output_plaintext = PlaintextList::new(0u64, PlaintextCount(polynomial_size.0));
///
/// // First create a decomposer working on the high 4 bits corresponding to our encoding.
/// let decomposer = SignedDecomposer::new(DecompositionBaseLog(2), DecompositionLevelCount(4));
///
/// decrypt_glwe_ciphertext(
///     &glwe_secret_key,
///     &output_glwe_ciphertext,
///     &mut output_plaintext,
/// );
/// output_plaintext
///     .iter_mut()
///     .for_each(|elt| *elt.0 = decomposer.closest_representable(*elt.0));
///
/// // Get the raw vector
/// let mut cleartext = output_plaintext.into_container();
/// // Remove the encoding
/// cleartext
///     .iter_mut()
///     .for_each(|elt| *elt = *elt >> output_log_delta);
/// // Get the list immutably
/// let cleartext = cleartext;
///
/// // Compute what the product should be
/// let pt1 = Polynomial::from_container(
///     plaintext_list_1
///         .into_container()
///         .iter()
///         .map(|&x| <u64 as CastInto<u128>>::cast_into(x))
///         .collect::<Vec<_>>(),
/// );
/// let pt2 = Polynomial::from_container(
///     plaintext_list_2
///         .into_container()
///         .iter()
///         .map(|&x| <u64 as CastInto<u128>>::cast_into(x))
///         .collect::<Vec<_>>(),
/// );
///
/// let mut product = Polynomial::new(0u128, polynomial_size);
/// polynomial_wrapping_mul(&mut product, &pt1, &pt2);
///
/// let mut scaled_product = Polynomial::new(0u64, polynomial_size);
/// scaled_product
///     .as_mut()
///     .iter_mut()
///     .zip(product.as_ref().iter())
///     .for_each(|(dest, &source)| {
///         *dest = u64::cast_from(source / <u64 as CastInto<u128>>::cast_into(scale))
///             >> output_log_delta
///     });
///
/// // Check we recovered the correct message
/// cleartext
///     .iter()
///     .zip(scaled_product.iter())
///     .for_each(|(&elt, coeff)| assert_eq!(elt, *coeff));
/// ```
pub fn tensor_mult_with_relin<InputCont, KeyCont, OutputCont, Scalar>(
    input_glwe_ciphertext_lhs: &GlweCiphertext<InputCont>,
    input_glwe_ciphertext_rhs: &GlweCiphertext<InputCont>,
    scale: Scalar,
    relinearisation_key: &GlweRelinearisationKey<KeyCont>,
    output_glwe_ciphertext: &mut GlweCiphertext<OutputCont>,
) where
    Scalar: UnsignedTorus + CastInto<u128> + CastFrom<u128>,
    InputCont: Container<Element = Scalar>,
    KeyCont: Container<Element = Scalar>,
    OutputCont: ContainerMut<Element = Scalar>,
{
    let tensor_output = glwe_tensor_product(
        &input_glwe_ciphertext_lhs,
        &input_glwe_ciphertext_rhs,
        scale,
    );
    glwe_relinearisation(&tensor_output, &relinearisation_key, output_glwe_ciphertext);
}

pub fn pack_lwe_list_into_glwe<InputCont, KeyCont, OutputCont, Scalar>(
    lwe_pksk: &LwePackingKeyswitchKey<KeyCont>,
    input_lwe_list1: &LweCiphertextList<InputCont>,
    output_pks: &mut GlweCiphertext<OutputCont>,
) where
    Scalar: UnsignedTorus + CastInto<usize>,
    KeyCont: Container<Element = Scalar>,
    InputCont: Container<Element = Scalar>,
    OutputCont: ContainerMut<Element = Scalar>,
{
    keyswitch_lwe_ciphertext_list_and_pack_in_glwe_ciphertext(
        &lwe_pksk,
        &input_lwe_list1,
        output_pks ,
    );
}

pub fn pack_lwe_list_into_glwe_tensor_mult_with_relin_pbs<InputCont, KeyCont1, KeyCont2, OutputCont, Scalar, AccCont>(
    lwe_pksk: &LwePackingKeyswitchKey<KeyCont1>,
    input_lwe_ciphertext_list1: &LweCiphertextList<InputCont>,
    input_lwe_ciphertext_list2: &LweCiphertextList<InputCont>,
    output_pks: &mut GlweCiphertext<OutputCont>,
    scale: Scalar,
    relinearisation_key: &GlweRelinearisationKey<KeyCont1>,
    output_relin: &mut GlweCiphertext<OutputCont>,
    extracted_sample: &mut LweCiphertext<OutputCont>,
    ksk: &LweKeyswitchKeyOwned<Scalar>,
    ks_result: &mut LweCiphertext<OutputCont>,
    accumulator:&GlweCiphertext<AccCont>,
    fourier_bsk: &FourierLweBootstrapKey<KeyCont2>,
    fft: FftView<'_>,
    buffers: &mut ComputationBuffers,
    output_pbs_ct: &mut LweCiphertext<OutputCont>,
) where
    Scalar: UnsignedTorus + CastInto<usize>,
    KeyCont1: Container<Element = Scalar>,
    KeyCont2: Container<Element = c64>,
    InputCont: Container<Element = Scalar>,
    OutputCont: ContainerMut<Element = Scalar>,
    OutputCont: Clone,
    AccCont: Container<Element = Scalar>,
{
    let mut packed_glwe1 = output_pks.clone();
    keyswitch_lwe_ciphertext_list_and_pack_in_glwe_ciphertext(
        &lwe_pksk,
        &input_lwe_ciphertext_list1,
        &mut packed_glwe1 ,
    );

    let mut packed_glwe2 = output_relin.clone();
    keyswitch_lwe_ciphertext_list_and_pack_in_glwe_ciphertext(
        &lwe_pksk,
        &input_lwe_ciphertext_list2,
        &mut packed_glwe2,
    );

    tensor_mult_with_relin(&packed_glwe1, &packed_glwe2, scale,relinearisation_key,output_relin);
            
    // Here we chose to extract sample at index 42 (corresponding to the MonomialDegree(42))
    extract_lwe_sample_from_glwe_ciphertext(&output_relin, extracted_sample, MonomialDegree(42));
    //let mut input_ks = extracted_sample.clone();
    keyswitch_lwe_ciphertext(&ksk, extracted_sample, ks_result);


    programmable_bootstrap_lwe_ciphertext_mem_optimized(
        &ks_result,
        output_pbs_ct,
        &accumulator.as_view(),
        &fourier_bsk,
        fft,
        buffers.stack(),
    )
}

pub fn pack_lwe_list_into_glwe_tensor_mult_with_relin_pbs_ks<InputCont, KeyCont1, KeyCont2, OutputCont, Scalar, AccCont>(
    lwe_pksk: &LwePackingKeyswitchKey<KeyCont1>,
    input_lwe_ciphertext_list1: &LweCiphertextList<InputCont>,
    input_lwe_ciphertext_list2: &LweCiphertextList<InputCont>,
    output_pks: &mut GlweCiphertext<OutputCont>,
    scale: Scalar,
    relinearisation_key: &GlweRelinearisationKey<KeyCont1>,
    output_relin: &mut GlweCiphertext<OutputCont>,
    extracted_sample: &mut LweCiphertext<OutputCont>,
    ksk1: &LweKeyswitchKeyOwned<Scalar>,
    ks_result1: &mut LweCiphertext<OutputCont>,
    accumulator:&GlweCiphertext<AccCont>,
    fourier_bsk: &FourierLweBootstrapKey<KeyCont2>,
    fft: FftView<'_>,
    buffers: &mut ComputationBuffers,
    output_pbs_ct: &mut LweCiphertext<OutputCont>,
    ksk2: &LweKeyswitchKeyOwned<Scalar>,
    ks_result2: &mut LweCiphertext<OutputCont>,
) where
    Scalar: UnsignedTorus + CastInto<usize>,
    KeyCont1: Container<Element = Scalar>,
    KeyCont2: Container<Element = c64>,
    InputCont: Container<Element = Scalar>,
    OutputCont: ContainerMut<Element = Scalar>,
    OutputCont: Clone,
    AccCont: Container<Element = Scalar>,
{
    let mut packed_glwe1 = output_pks.clone();
    keyswitch_lwe_ciphertext_list_and_pack_in_glwe_ciphertext(
        &lwe_pksk,
        &input_lwe_ciphertext_list1,
        &mut packed_glwe1 ,
    );

    let mut packed_glwe2 = output_pks.clone();
    keyswitch_lwe_ciphertext_list_and_pack_in_glwe_ciphertext(
        &lwe_pksk,
        &input_lwe_ciphertext_list2,
        &mut packed_glwe2,
    );

    tensor_mult_with_relin(&packed_glwe1, &packed_glwe1, scale,relinearisation_key,output_relin);
            
    // Here we chose to extract sample at index 42 (corresponding to the MonomialDegree(42))
    extract_lwe_sample_from_glwe_ciphertext(&output_relin, extracted_sample, MonomialDegree(42));
    //let mut input_ks = extracted_sample.clone();
    keyswitch_lwe_ciphertext(&ksk1, extracted_sample, ks_result1);

    programmable_bootstrap_lwe_ciphertext_mem_optimized(
        &ks_result1,
        output_pbs_ct,
        &accumulator.as_view(),
        &fourier_bsk,
        fft,
        buffers.stack(),
    );

    keyswitch_lwe_ciphertext(&ksk2, output_pbs_ct, ks_result2);
}

//clot21 circuit without packing ks scenario a
pub fn glwe_tensor_mult_with_relin_pbs_ks_a<InputCont, KeyCont1, KeyCont2, OutputCont, Scalar, AccCont>(
    packed_glwe1: &GlweCiphertext<InputCont>,
    packed_glwe2: &GlweCiphertext<InputCont>,
    scale: Scalar,
    relinearisation_key: &GlweRelinearisationKey<KeyCont1>,
    output_relin: &mut GlweCiphertext<OutputCont>,
    extracted_sample: &mut LweCiphertext<OutputCont>,
    ksk1: &LweKeyswitchKeyOwned<Scalar>,
    ks_result1: &mut LweCiphertext<OutputCont>,
    accumulator:&GlweCiphertext<AccCont>,
    fourier_bsk: &FourierLweBootstrapKey<KeyCont2>,
    fft: FftView<'_>,
    buffers: &mut ComputationBuffers,
    output_pbs_ct: &mut LweCiphertext<OutputCont>,
) where
    Scalar: UnsignedTorus + CastInto<usize>,
    KeyCont1: Container<Element = Scalar>,
    KeyCont2: Container<Element = c64>,
    InputCont: Container<Element = Scalar>,
    OutputCont: ContainerMut<Element = Scalar>,
    OutputCont: Clone,
    AccCont: Container<Element = Scalar>,
{

    tensor_mult_with_relin(&packed_glwe1, &packed_glwe1, scale,relinearisation_key,output_relin);
            
    // Here we chose to extract sample at index 42 (corresponding to the MonomialDegree(42))
    extract_lwe_sample_from_glwe_ciphertext(&output_relin, extracted_sample, MonomialDegree(42));
    
    keyswitch_lwe_ciphertext(&ksk1, extracted_sample, ks_result1);

    programmable_bootstrap_lwe_ciphertext_mem_optimized(
        &ks_result1,
        output_pbs_ct,
        &accumulator.as_view(),
        &fourier_bsk,
        fft,
        buffers.stack(),
    );
}

//clot21 circuit without packing ks scenario c
pub fn glwe_tensor_mult_with_relin_pbs_ks_c<InputCont, KeyCont1, KeyCont2, OutputCont, Scalar, AccCont>(
    packed_glwe1: &GlweCiphertext<InputCont>,
    packed_glwe2: &GlweCiphertext<InputCont>,
    scale: Scalar,
    relinearisation_key: &GlweRelinearisationKey<KeyCont1>,
    output_relin: &mut GlweCiphertext<OutputCont>,
    extracted_sample: &mut LweCiphertext<OutputCont>,
    ksk1: &LweKeyswitchKeyOwned<Scalar>,
    ks_result1: &mut LweCiphertext<OutputCont>,
    accumulator:&GlweCiphertext<AccCont>,
    fourier_bsk: &FourierLweBootstrapKey<KeyCont2>,
    fft: FftView<'_>,
    buffers: &mut ComputationBuffers,
    output_pbs_ct: &mut LweCiphertext<OutputCont>,
    ksk2: &LweKeyswitchKeyOwned<Scalar>,
    ks_result2: &mut LweCiphertext<OutputCont>,
) where
    Scalar: UnsignedTorus + CastInto<usize>,
    KeyCont1: Container<Element = Scalar>,
    KeyCont2: Container<Element = c64>,
    InputCont: Container<Element = Scalar>,
    OutputCont: ContainerMut<Element = Scalar>,
    OutputCont: Clone,
    AccCont: Container<Element = Scalar>,
{

    tensor_mult_with_relin(&packed_glwe1, &packed_glwe1, scale,relinearisation_key,output_relin);
            
    // Here we chose to extract sample at index 42 (corresponding to the MonomialDegree(42))
    extract_lwe_sample_from_glwe_ciphertext(&output_relin, extracted_sample, MonomialDegree(42));
    
    keyswitch_lwe_ciphertext(&ksk1, extracted_sample, ks_result1);

    programmable_bootstrap_lwe_ciphertext_mem_optimized(
        &ks_result1,
        output_pbs_ct,
        &accumulator.as_view(),
        &fourier_bsk,
        fft,
        buffers.stack(),
    );
    
    keyswitch_lwe_ciphertext(&ksk2, output_pbs_ct, ks_result2);
}

pub fn square_trick<Scalar, InputCont, OutputCont, AccCont, KeyCont>(
    lwe_lhs: &LweCiphertext<InputCont>,
    lwe_rhs: &LweCiphertext<InputCont>,
    nb_mults: i8,
    ksk1: &LweKeyswitchKeyOwned<Scalar>,
    ks_result1: &mut LweCiphertext<OutputCont>,
    ksk2: &LweKeyswitchKeyOwned<Scalar>,
    ks_result2: &mut LweCiphertext<OutputCont>,
    accumulator1: &GlweCiphertext<AccCont>,
    accumulator2: &GlweCiphertext<AccCont>,
    fourier_bsk1: &FourierLweBootstrapKey<KeyCont>,
    fourier_bsk2: &FourierLweBootstrapKey<KeyCont>,  
    sq_sum: &mut LweCiphertext<OutputCont>,
    sq_subtraction: &mut LweCiphertext<OutputCont>,
    ksk: &LweKeyswitchKeyOwned<Scalar>,
    ks_result: &mut LweCiphertext<OutputCont>,
    accumulator: &GlweCiphertext<AccCont>,
    fourier_bsk: &FourierLweBootstrapKey<KeyCont>,
    fft: FftView<'_>,
    buffers: &mut ComputationBuffers,
    output_pbs_ct: &mut LweCiphertext<OutputCont>,
) where
Scalar: UnsignedTorus + CastInto<usize>,
KeyCont: Container<Element = c64>,
InputCont: Container<Element = Scalar> + ContainerMut,
OutputCont: ContainerMut<Element = Scalar>,
OutputCont: Clone,
AccCont: Container<Element = Scalar>,
{
    let mut result_sum = sq_sum.clone();
    for _ in 0..nb_mults
    {
        //let mul_cleartext = Scalar::ONE;
        let mut sum = sq_sum.clone();
        lwe_ciphertext_add(&mut sum, &lwe_lhs, &lwe_rhs);
    
        keyswitch_lwe_ciphertext(&ksk1, &mut sum, ks_result1);

        programmable_bootstrap_lwe_ciphertext_mem_optimized(
            &ks_result1,
            sq_sum,
            &accumulator1.as_view(),
            &fourier_bsk1,
            fft,
            buffers.stack(),
        );
        //not needed can be done in pbs
        //lwe_ciphertext_cleartext_mul_assign(sq_sum, Cleartext(mul_cleartext));

        let mut subtraction = sq_subtraction.clone();
        lwe_ciphertext_sub(&mut subtraction, &lwe_lhs, &lwe_rhs);
    
        keyswitch_lwe_ciphertext(&ksk2, &mut subtraction, ks_result2);
        programmable_bootstrap_lwe_ciphertext_mem_optimized(
            &ks_result2,
            sq_subtraction,
            &accumulator2.as_view(),
            &fourier_bsk2,
            fft,
            buffers.stack(),
        );
        //not needed can be done in pbs
        //lwe_ciphertext_cleartext_mul_assign(sq_subtraction, Cleartext(mul_cleartext));
    
        //lwe_ciphertext_add(&mut result_sum, &sq_sum, &sq_subtraction);
        lwe_ciphertext_add_assign(&mut result_sum, &sq_sum);
        lwe_ciphertext_add_assign(&mut result_sum, &sq_subtraction);
    }
    
    let mut result =result_sum.clone();
    keyswitch_lwe_ciphertext(&ksk, &mut result, ks_result);

    programmable_bootstrap_lwe_ciphertext_mem_optimized(
        &ks_result,
        output_pbs_ct,
        &accumulator.as_view(),
        &fourier_bsk,
        fft,
        buffers.stack(),
    );
}

