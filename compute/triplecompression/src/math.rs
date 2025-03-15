use std::ops::MulAssign;
use lambdaworks_math::field::element::FieldElement;
use lambdaworks_math::field::fields::fft_friendly::stark_252_prime_field::Stark252PrimeField;
use rayon::prelude::*;

// TODO: Replace with: https://docs.rs/optimath/latest/optimath/#examples
pub(crate) fn matrix_vector_mul(
    matrix: &Vec<Vec<FieldElement<Stark252PrimeField>>>,
    vector: &Vec<FieldElement<Stark252PrimeField>>,
) -> Vec<FieldElement<Stark252PrimeField>> {
    // Check if the matrix is empty
    assert!(!matrix.is_empty(), "Matrix cannot be empty");

    // Check if all rows in the matrix have the same length
    let row_length = matrix[0].len();
    assert!(matrix.iter().all(|row| row.len() == row_length), "All rows in the matrix must have the same length");

    // Check if the vector length matches the number of columns in the matrix
    assert_eq!(row_length, vector.len(), "Vector length must match the number of columns in the matrix");

    matrix
        .par_iter()
        .map(|row| {
            row.iter()
                .zip(vector.iter())
                .map(|(a, b)| *a * *b)
                .fold(FieldElement::<Stark252PrimeField>::zero(), |acc, x| acc + x)
        })
        .collect()
}

pub(crate) fn dot_product(
    a: &Vec<FieldElement<Stark252PrimeField>>,
    b: &Vec<FieldElement<Stark252PrimeField>>,
) -> FieldElement<Stark252PrimeField> {
    // Assert that the vectors have the same length
    assert_eq!(a.len(), b.len(), "Vectors must have the same length");

    // Compute the dot product
    a.iter()
        .zip(b.iter())
        .map(|(x, y)| *x * *y)
        .fold(FieldElement::<Stark252PrimeField>::zero(), |acc, x| acc + x)
}

pub(crate) fn evaluate_polynomial_from_coefficients_at_position(
    coefficients: Vec<FieldElement<Stark252PrimeField>>,
    evaluation_point: FieldElement<Stark252PrimeField>,
) -> FieldElement<Stark252PrimeField> {
    let n = coefficients.len();

    if n <= 100 {
        let mut result = FieldElement::<Stark252PrimeField>::zero();
        let mut x_power = FieldElement::<Stark252PrimeField>::one();

        for coefficient in coefficients {
            result = result + coefficient * x_power;
            x_power = x_power * evaluation_point;
        }
        return result;
    }

    let mut powers = Vec::with_capacity(n);
    let mut current_power = FieldElement::<Stark252PrimeField>::one();
    powers.push(current_power);

    for _ in 1..n {
        current_power = current_power * evaluation_point;
        powers.push(current_power);
    }

    coefficients.par_iter()
        .zip(powers.par_iter())
        .map(|(coeff, power)| *coeff * *power)
        .reduce(|| FieldElement::<Stark252PrimeField>::zero(), |a, b| a + b)
}


/// Interpolates a polynomial by solving a system of linear equations in a finite field.
///
/// # Arguments
///
/// * `shares` - A vector of (x, y) coordinates representing the shares.
/// * `modulus` - The modulus for the finite field.
///
/// # Returns
///
/// A vector of coefficients of the interpolated polynomial, from lowest to highest degree.
pub(crate) fn interpolate_polynomial(
    shares: Vec<(FieldElement<Stark252PrimeField>, FieldElement<Stark252PrimeField>)>,
) -> Vec<FieldElement<Stark252PrimeField>> {
    let n = shares.len();
    let mut matrix = vec![vec![FieldElement::<Stark252PrimeField>::zero(); n + 1]; n];

    // Populate the matrix
    for (i, &(x, y)) in shares.iter().enumerate() {
        let mut x_power = FieldElement::<Stark252PrimeField>::one();
        for j in 0..n {
            matrix[i][j] = x_power;
            x_power = x_power * x;
        }
        matrix[i][n] = y;
    }

    // Perform Gaussian elimination
    for i in 0..n {
        // Find pivot
        let mut pivot_row = i;
        for j in i + 1..n {
            if matrix[j][i] != FieldElement::<Stark252PrimeField>::zero() {
                pivot_row = j;
                break;
            }
        }

        // Swap rows if necessary
        if pivot_row != i {
            matrix.swap(i, pivot_row);
        }

        let pivot = matrix[i][i];
        let pivot_inv = pivot.inv().unwrap(); // Unwrap the Result

        // Normalize pivot row
        for j in i..=n {
            matrix[i][j] = matrix[i][j] * pivot_inv;
        }

        // Eliminate in other rows
        for k in 0..n {
            if k != i {
                let factor = matrix[k][i];
                for j in i..=n {
                    matrix[k][j] = matrix[k][j] - factor * matrix[i][j];
                }
            }
        }
    }

    // Extract solution
    let mut result: Vec<FieldElement<Stark252PrimeField>> = matrix.iter().map(|row| row[n]).collect();

    // Remove leading zero coefficients
    while result.len() > 1 && result.last() == Some(&FieldElement::<Stark252PrimeField>::zero()) {
        result.pop();
    }

    result
}

pub(crate) fn generate_vandermonde_matrix(rows: usize, cols: usize) -> Vec<Vec<FieldElement<Stark252PrimeField>>> {
    (0..rows)
        .into_par_iter()
        .map(|i| {
            let base = FieldElement::<Stark252PrimeField>::from(i as u64 + 1);
            (0..cols)
                .map(|j| base.pow(j as u64))
                .collect()
        })
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;
    
    #[test]
    fn test_matrix_vector_mul() {
        use lambdaworks_math::field::element::FieldElement;
        use lambdaworks_math::field::fields::fft_friendly::stark_252_prime_field::Stark252PrimeField;

        // Test 1: Simple 2x2 matrix
        let matrix = vec![
            vec![
                FieldElement::<Stark252PrimeField>::from(1u64),
                FieldElement::<Stark252PrimeField>::from(2u64),
            ],
            vec![
                FieldElement::<Stark252PrimeField>::from(3u64),
                FieldElement::<Stark252PrimeField>::from(4u64),
            ],
        ];

        let vector = vec![
            FieldElement::<Stark252PrimeField>::from(5u64),
            FieldElement::<Stark252PrimeField>::from(6u64),
        ];

        // [1, 2] * [5, 6] = 1*5 + 2*6 = 5 + 12 = 17
        // [3, 4] * [5, 6] = 3*5 + 4*6 = 15 + 24 = 39
        let expected = vec![
            FieldElement::<Stark252PrimeField>::from(17u64),
            FieldElement::<Stark252PrimeField>::from(39u64),
        ];

        let result = matrix_vector_mul(&matrix, &vector);
        assert_eq!(result, expected);

        // Test 2: 1x1 matrix (edge case)
        let matrix_1x1 = vec![vec![FieldElement::<Stark252PrimeField>::from(7u64)]];
        let vector_1 = vec![FieldElement::<Stark252PrimeField>::from(8u64)];
        let expected_1 = vec![FieldElement::<Stark252PrimeField>::from(56u64)]; // 7*8 = 56
        let result_1 = matrix_vector_mul(&matrix_1x1, &vector_1);
        assert_eq!(result_1, expected_1);

        // Test 3: Larger matrix for parallelism
        let n = 10; // Size of matrix
        let matrix_large = (0..n)
            .map(|i| {
                (0..n)
                    .map(|j| FieldElement::<Stark252PrimeField>::from((i * n + j + 1) as u64))
                    .collect()
            })
            .collect();

        let vector_large = (0..n)
            .map(|i| FieldElement::<Stark252PrimeField>::from((i + 1) as u64))
            .collect();

        // Calculate expected result manually for verification
        let expected_large = (0..n)
            .map(|i| {
                (0..n)
                    .map(|j| {
                        let a = (i * n + j + 1) as u64;
                        let b = (j + 1) as u64;
                        FieldElement::<Stark252PrimeField>::from(a) * FieldElement::<Stark252PrimeField>::from(b)
                    })
                    .fold(FieldElement::<Stark252PrimeField>::zero(), |acc, x| acc + x)
            })
            .collect::<Vec<_>>();

        let result_large = matrix_vector_mul(&matrix_large, &vector_large);
        assert_eq!(result_large, expected_large);

        // Test 4: Matrix with zero values
        let matrix_zeros = vec![
            vec![
                FieldElement::<Stark252PrimeField>::zero(),
                FieldElement::<Stark252PrimeField>::zero(),
            ],
            vec![
                FieldElement::<Stark252PrimeField>::zero(),
                FieldElement::<Stark252PrimeField>::zero(),
            ],
        ];

        let result_zeros = matrix_vector_mul(&matrix_zeros, &vector);
        assert_eq!(
            result_zeros,
            vec![
                FieldElement::<Stark252PrimeField>::zero(),
                FieldElement::<Stark252PrimeField>::zero(),
            ]
        );
    }

    #[test]
    #[should_panic(expected = "Matrix cannot be empty")]
    fn test_matrix_vector_mul_empty_matrix() {
        let empty_matrix: Vec<Vec<FieldElement<Stark252PrimeField>>> = vec![];
        let vector = vec![FieldElement::<Stark252PrimeField>::from(1u64)];

        matrix_vector_mul(&empty_matrix, &vector);
    }

    #[test]
    #[should_panic(expected = "All rows in the matrix must have the same length")]
    fn test_matrix_vector_mul_uneven_rows() {
        let uneven_matrix = vec![
            vec![
                FieldElement::<Stark252PrimeField>::from(1u64),
                FieldElement::<Stark252PrimeField>::from(2u64),
            ],
            vec![FieldElement::<Stark252PrimeField>::from(3u64)], // One element only
        ];
        let vector = vec![
            FieldElement::<Stark252PrimeField>::from(4u64),
            FieldElement::<Stark252PrimeField>::from(5u64),
        ];

        matrix_vector_mul(&uneven_matrix, &vector);
    }

    #[test]
    #[should_panic(expected = "Vector length must match the number of columns in the matrix")]
    fn test_matrix_vector_mul_dimension_mismatch() {
        let matrix = vec![
            vec![
                FieldElement::<Stark252PrimeField>::from(1u64),
                FieldElement::<Stark252PrimeField>::from(2u64),
            ],
            vec![
                FieldElement::<Stark252PrimeField>::from(3u64),
                FieldElement::<Stark252PrimeField>::from(4u64),
            ],
        ];
        let vector = vec![FieldElement::<Stark252PrimeField>::from(5u64)]; // Should have two elements

        matrix_vector_mul(&matrix, &vector);
    }

    #[test]
    fn test_dot_product() {
        use lambdaworks_math::field::element::FieldElement;
        use lambdaworks_math::field::fields::fft_friendly::stark_252_prime_field::Stark252PrimeField;

        // Test 1: Basic 2-element vectors
        let vec_a = vec![
            FieldElement::<Stark252PrimeField>::from(1u64),
            FieldElement::<Stark252PrimeField>::from(2u64),
        ];
        let vec_b = vec![
            FieldElement::<Stark252PrimeField>::from(3u64),
            FieldElement::<Stark252PrimeField>::from(4u64),
        ];
        // 1*3 + 2*4 = 11
        let expected = FieldElement::<Stark252PrimeField>::from(11u64);
        assert_eq!(dot_product(&vec_a, &vec_b), expected);

        // Test 2: Vectors with zeros
        let vec_c = vec![
            FieldElement::<Stark252PrimeField>::from(1u64),
            FieldElement::<Stark252PrimeField>::zero(),
            FieldElement::<Stark252PrimeField>::from(3u64),
        ];
        let vec_d = vec![
            FieldElement::<Stark252PrimeField>::zero(),
            FieldElement::<Stark252PrimeField>::from(2u64),
            FieldElement::<Stark252PrimeField>::zero(),
        ];
        // 1*0 + 0*2 + 3*0 = 0
        let expected_zero = FieldElement::<Stark252PrimeField>::zero();
        assert_eq!(dot_product(&vec_c, &vec_d), expected_zero);

        // Test 3: Single element vectors
        let vec_e = vec![FieldElement::<Stark252PrimeField>::from(5u64)];
        let vec_f = vec![FieldElement::<Stark252PrimeField>::from(6u64)];
        // 5*6 = 30
        let expected_single = FieldElement::<Stark252PrimeField>::from(30u64);
        assert_eq!(dot_product(&vec_e, &vec_f), expected_single);

        // Test 4: Larger vectors for more complex dot product
        let vec_g = (0..10)
            .map(|i| FieldElement::<Stark252PrimeField>::from(i as u64 + 1))
            .collect();
        let vec_h = (0..10)
            .map(|i| FieldElement::<Stark252PrimeField>::from((i as u64 + 1) * 2))
            .collect();
        // 1*2 + 2*4 + 3*6 + ... + 10*20 = 770
        let expected_large = FieldElement::<Stark252PrimeField>::from(770u64);
        assert_eq!(dot_product(&vec_g, &vec_h), expected_large);

        // Test 5: Vectors with identical elements
        let vec_i = vec![
            FieldElement::<Stark252PrimeField>::from(3u64); 5
        ];
        let vec_j = vec![
            FieldElement::<Stark252PrimeField>::from(2u64); 5
        ];
        // 3*2 * 5 = 30
        let expected_identical = FieldElement::<Stark252PrimeField>::from(30u64);
        assert_eq!(dot_product(&vec_i, &vec_j), expected_identical);
    }

    #[test]
    #[should_panic(expected = "Vectors must have the same length")]
    fn test_dot_product_different_lengths() {
        let vec_a = vec![
            FieldElement::<Stark252PrimeField>::from(1u64),
            FieldElement::<Stark252PrimeField>::from(2u64),
        ];
        let vec_b = vec![
            FieldElement::<Stark252PrimeField>::from(3u64),
        ];

        dot_product(&vec_a, &vec_b); // Should panic
    }
    
    #[test]
    fn test_evaluate_polynomial_from_coefficients_at_position() {
        use lambdaworks_math::field::element::FieldElement;
        use lambdaworks_math::field::fields::fft_friendly::stark_252_prime_field::Stark252PrimeField;

        // Test 1: Constant polynomial f(x) = 42
        let constant_poly = vec![FieldElement::<Stark252PrimeField>::from(42u64)];
        let x = FieldElement::<Stark252PrimeField>::from(7u64);
        let expected = FieldElement::<Stark252PrimeField>::from(42u64);
        let result = evaluate_polynomial_from_coefficients_at_position(constant_poly, x);
        assert_eq!(result, expected);

        // Test 2: Linear polynomial f(x) = 3x + 2
        let linear_poly = vec![
            FieldElement::<Stark252PrimeField>::from(2u64), // constant term
            FieldElement::<Stark252PrimeField>::from(3u64), // x coefficient
        ];
        let x = FieldElement::<Stark252PrimeField>::from(5u64);
        // f(5) = 3*5 + 2 = 17
        let expected = FieldElement::<Stark252PrimeField>::from(17u64);
        let result = evaluate_polynomial_from_coefficients_at_position(linear_poly, x);
        assert_eq!(result, expected);

        // Test 3: Quadratic polynomial f(x) = 2x² + 3x + 1
        let quadratic_poly = vec![
            FieldElement::<Stark252PrimeField>::from(1u64), // constant term
            FieldElement::<Stark252PrimeField>::from(3u64), // x coefficient
            FieldElement::<Stark252PrimeField>::from(2u64), // x² coefficient
        ];
        let x = FieldElement::<Stark252PrimeField>::from(4u64);
        // f(4) = 2*16 + 3*4 + 1 = 32 + 12 + 1 = 45
        let expected = FieldElement::<Stark252PrimeField>::from(45u64);
        let result = evaluate_polynomial_from_coefficients_at_position(quadratic_poly, x);
        assert_eq!(result, expected);

        // Test 4: Zero polynomial f(x) = 0
        let zero_poly = vec![FieldElement::<Stark252PrimeField>::zero()];
        let x = FieldElement::<Stark252PrimeField>::from(100u64);
        let expected = FieldElement::<Stark252PrimeField>::zero();
        let result = evaluate_polynomial_from_coefficients_at_position(zero_poly, x);
        assert_eq!(result, expected);

        // Test 5: Evaluation at x=0
        let poly = vec![
            FieldElement::<Stark252PrimeField>::from(7u64),
            FieldElement::<Stark252PrimeField>::from(5u64),
            FieldElement::<Stark252PrimeField>::from(9u64),
        ];
        let x = FieldElement::<Stark252PrimeField>::zero();
        // f(0) = 7 + 5*0 + 9*0² = 7
        let expected = FieldElement::<Stark252PrimeField>::from(7u64);
        let result = evaluate_polynomial_from_coefficients_at_position(poly, x);
        assert_eq!(result, expected);

        // Test 6: Evaluation at x=1
        let poly = vec![
            FieldElement::<Stark252PrimeField>::from(7u64),
            FieldElement::<Stark252PrimeField>::from(5u64),
            FieldElement::<Stark252PrimeField>::from(9u64),
        ];
        let x = FieldElement::<Stark252PrimeField>::one();
        // f(1) = 7 + 5*1 + 9*1² = 21
        let expected = FieldElement::<Stark252PrimeField>::from(21u64);
        let result = evaluate_polynomial_from_coefficients_at_position(poly, x);
        assert_eq!(result, expected);

        // Test 7: Larger polynomial to test the parallel path (n > 100)
        // Create a polynomial with 101 coefficients: f(x) = 1 + 2x + 3x² + ... + 101x¹⁰⁰
        let large_poly: Vec<FieldElement<Stark252PrimeField>> = (1..=101)
            .map(|i| FieldElement::<Stark252PrimeField>::from(i as u64))
            .collect();

        let x = FieldElement::<Stark252PrimeField>::from(2u64);

        // Compute expected value using another method for verification
        let mut expected = FieldElement::<Stark252PrimeField>::zero();
        let mut x_power = FieldElement::<Stark252PrimeField>::one();
        for coeff in &large_poly {
            expected = expected + *coeff * x_power;
            x_power = x_power * x;
        }

        let result = evaluate_polynomial_from_coefficients_at_position(large_poly, x);
        assert_eq!(result, expected);

        // Test 8: Ensure both calculation paths give same result for a polynomial at the threshold
        let threshold_poly: Vec<FieldElement<Stark252PrimeField>> = (1..=100)
            .map(|i| FieldElement::<Stark252PrimeField>::from(i as u64))
            .collect();

        let x = FieldElement::<Stark252PrimeField>::from(3u64);

        // Force direct calculation
        let mut direct_result = FieldElement::<Stark252PrimeField>::zero();
        let mut x_power = FieldElement::<Stark252PrimeField>::one();

        for coefficient in &threshold_poly {
            direct_result = direct_result + *coefficient * x_power;
            x_power = x_power * x;
        }

        let function_result = evaluate_polynomial_from_coefficients_at_position(threshold_poly, x);
        assert_eq!(direct_result, function_result);
    }

    #[test]
    fn test_interpolate_polynomial() {
        use lambdaworks_math::field::element::FieldElement;
        use lambdaworks_math::field::fields::fft_friendly::stark_252_prime_field::Stark252PrimeField;

        // Test 1: Linear polynomial y = 2x + 3
        let linear_points = vec![
            (FieldElement::<Stark252PrimeField>::from(1u64), FieldElement::<Stark252PrimeField>::from(5u64)), // 2*1 + 3 = 5
            (FieldElement::<Stark252PrimeField>::from(2u64), FieldElement::<Stark252PrimeField>::from(7u64)), // 2*2 + 3 = 7
        ];

        let linear_coeffs = interpolate_polynomial(linear_points);
        assert_eq!(linear_coeffs.len(), 2);
        assert_eq!(linear_coeffs[0], FieldElement::<Stark252PrimeField>::from(3u64)); // constant term
        assert_eq!(linear_coeffs[1], FieldElement::<Stark252PrimeField>::from(2u64)); // x coefficient

        // Test 2: Quadratic polynomial y = 3x² + 2x + 1
        let quadratic_points = vec![
            (FieldElement::<Stark252PrimeField>::from(0u64), FieldElement::<Stark252PrimeField>::from(1u64)), // 3*0² + 2*0 + 1 = 1
            (FieldElement::<Stark252PrimeField>::from(1u64), FieldElement::<Stark252PrimeField>::from(6u64)), // 3*1² + 2*1 + 1 = 6
            (FieldElement::<Stark252PrimeField>::from(2u64), FieldElement::<Stark252PrimeField>::from(17u64)), // 3*2² + 2*2 + 1 = 17
        ];

        let quadratic_coeffs = interpolate_polynomial(quadratic_points);
        assert_eq!(quadratic_coeffs.len(), 3);
        assert_eq!(quadratic_coeffs[0], FieldElement::<Stark252PrimeField>::from(1u64)); // constant term
        assert_eq!(quadratic_coeffs[1], FieldElement::<Stark252PrimeField>::from(2u64)); // x coefficient
        assert_eq!(quadratic_coeffs[2], FieldElement::<Stark252PrimeField>::from(3u64)); // x² coefficient

        // Test 3: Cubic polynomial y = x³ + 2x² + 3x + 4
        let cubic_points = vec![
            (FieldElement::<Stark252PrimeField>::from(0u64), FieldElement::<Stark252PrimeField>::from(4u64)),
            (FieldElement::<Stark252PrimeField>::from(1u64), FieldElement::<Stark252PrimeField>::from(10u64)),
            (FieldElement::<Stark252PrimeField>::from(2u64), FieldElement::<Stark252PrimeField>::from(26u64)),
            (FieldElement::<Stark252PrimeField>::from(3u64), FieldElement::<Stark252PrimeField>::from(58u64)),
        ];

        let cubic_coeffs = interpolate_polynomial(cubic_points);
        assert_eq!(cubic_coeffs.len(), 4);
        assert_eq!(cubic_coeffs[0], FieldElement::<Stark252PrimeField>::from(4u64));
        assert_eq!(cubic_coeffs[1], FieldElement::<Stark252PrimeField>::from(3u64));
        assert_eq!(cubic_coeffs[2], FieldElement::<Stark252PrimeField>::from(2u64));
        assert_eq!(cubic_coeffs[3], FieldElement::<Stark252PrimeField>::from(1u64));

        // Test 4: Constant polynomial y = 42
        let constant_points = vec![
            (FieldElement::<Stark252PrimeField>::from(1u64), FieldElement::<Stark252PrimeField>::from(42u64)),
            (FieldElement::<Stark252PrimeField>::from(2u64), FieldElement::<Stark252PrimeField>::from(42u64)),
        ];

        let constant_coeffs = interpolate_polynomial(constant_points);
        assert_eq!(constant_coeffs.len(), 1);
        assert_eq!(constant_coeffs[0], FieldElement::<Stark252PrimeField>::from(42u64));

        // Test 5: Polynomial with leading zero coefficients y = x² + 0x³
        let zero_leading_points = vec![
            (FieldElement::<Stark252PrimeField>::from(0u64), FieldElement::<Stark252PrimeField>::from(0u64)),
            (FieldElement::<Stark252PrimeField>::from(1u64), FieldElement::<Stark252PrimeField>::from(1u64)),
            (FieldElement::<Stark252PrimeField>::from(2u64), FieldElement::<Stark252PrimeField>::from(4u64)),
            (FieldElement::<Stark252PrimeField>::from(3u64), FieldElement::<Stark252PrimeField>::from(9u64)),
        ];

        let zero_leading_coeffs = interpolate_polynomial(zero_leading_points);
        assert_eq!(zero_leading_coeffs.len(), 3);
        assert_eq!(zero_leading_coeffs[0], FieldElement::<Stark252PrimeField>::from(0u64));
        assert_eq!(zero_leading_coeffs[1], FieldElement::<Stark252PrimeField>::from(0u64));
        assert_eq!(zero_leading_coeffs[2], FieldElement::<Stark252PrimeField>::from(1u64));

        // Test 6: Verification by evaluating at original points
        let test_points = vec![
            (FieldElement::<Stark252PrimeField>::from(5u64), FieldElement::<Stark252PrimeField>::from(37u64)),
            (FieldElement::<Stark252PrimeField>::from(10u64), FieldElement::<Stark252PrimeField>::from(122u64)),
            (FieldElement::<Stark252PrimeField>::from(15u64), FieldElement::<Stark252PrimeField>::from(247u64)),
        ];

        let test_coeffs = interpolate_polynomial(test_points.clone());

        // Verify that the polynomial evaluates to the correct y-values at the sample points
        for (x, expected_y) in test_points {
            let result = evaluate_polynomial_from_coefficients_at_position(test_coeffs.clone(), x);
            assert_eq!(result, expected_y);
        }
    }

    #[test]
    fn test_generate_vandermonde_matrix() {
        use lambdaworks_math::field::element::FieldElement;
        use lambdaworks_math::field::fields::fft_friendly::stark_252_prime_field::Stark252PrimeField;

        // Test 1: Small 2x2 matrix
        let matrix_2x2 = generate_vandermonde_matrix(2, 2);
        assert_eq!(matrix_2x2.len(), 2);
        assert_eq!(matrix_2x2[0].len(), 2);

        // First row: [1, 1]  (1^0, 1^1)
        assert_eq!(matrix_2x2[0][0], FieldElement::<Stark252PrimeField>::from(1u64));
        assert_eq!(matrix_2x2[0][1], FieldElement::<Stark252PrimeField>::from(1u64));

        // Second row: [1, 2]  (2^0, 2^1)
        assert_eq!(matrix_2x2[1][0], FieldElement::<Stark252PrimeField>::from(1u64));
        assert_eq!(matrix_2x2[1][1], FieldElement::<Stark252PrimeField>::from(2u64));

        // Test 2: 3x3 matrix
        let matrix_3x3 = generate_vandermonde_matrix(3, 3);
        assert_eq!(matrix_3x3.len(), 3);
        assert_eq!(matrix_3x3[0].len(), 3);

        // First row: [1, 1, 1]  (1^0, 1^1, 1^2)
        assert_eq!(matrix_3x3[0][0], FieldElement::<Stark252PrimeField>::from(1u64));
        assert_eq!(matrix_3x3[0][1], FieldElement::<Stark252PrimeField>::from(1u64));
        assert_eq!(matrix_3x3[0][2], FieldElement::<Stark252PrimeField>::from(1u64));

        // Second row: [1, 2, 4]  (2^0, 2^1, 2^2)
        assert_eq!(matrix_3x3[1][0], FieldElement::<Stark252PrimeField>::from(1u64));
        assert_eq!(matrix_3x3[1][1], FieldElement::<Stark252PrimeField>::from(2u64));
        assert_eq!(matrix_3x3[1][2], FieldElement::<Stark252PrimeField>::from(4u64));

        // Third row: [1, 3, 9]  (3^0, 3^1, 3^2)
        assert_eq!(matrix_3x3[2][0], FieldElement::<Stark252PrimeField>::from(1u64));
        assert_eq!(matrix_3x3[2][1], FieldElement::<Stark252PrimeField>::from(3u64));
        assert_eq!(matrix_3x3[2][2], FieldElement::<Stark252PrimeField>::from(9u64));

        // Test 3: Rectangular matrix (more rows than columns)
        let matrix_4x2 = generate_vandermonde_matrix(4, 2);
        assert_eq!(matrix_4x2.len(), 4);
        assert_eq!(matrix_4x2[0].len(), 2);

        // Check first column is all ones
        for i in 0..4 {
            assert_eq!(matrix_4x2[i][0], FieldElement::<Stark252PrimeField>::from(1u64));
        }

        // Check second column is powers of base
        for i in 0..4 {
            assert_eq!(matrix_4x2[i][1], FieldElement::<Stark252PrimeField>::from((i as u64) + 1));
        }

        // Test 4: Rectangular matrix (more columns than rows)
        let matrix_2x4 = generate_vandermonde_matrix(2, 4);
        assert_eq!(matrix_2x4.len(), 2);
        assert_eq!(matrix_2x4[0].len(), 4);

        // First row: [1, 1, 1, 1] (1^0, 1^1, 1^2, 1^3)
        for j in 0..4 {
            assert_eq!(matrix_2x4[0][j], FieldElement::<Stark252PrimeField>::from(1u64));
        }

        // Second row: [1, 2, 4, 8] (2^0, 2^1, 2^2, 2^3)
        assert_eq!(matrix_2x4[1][0], FieldElement::<Stark252PrimeField>::from(1u64));
        assert_eq!(matrix_2x4[1][1], FieldElement::<Stark252PrimeField>::from(2u64));
        assert_eq!(matrix_2x4[1][2], FieldElement::<Stark252PrimeField>::from(4u64));
        assert_eq!(matrix_2x4[1][3], FieldElement::<Stark252PrimeField>::from(8u64));

        // Test 5: Edge case - 1x1 matrix
        let matrix_1x1 = generate_vandermonde_matrix(1, 1);
        assert_eq!(matrix_1x1.len(), 1);
        assert_eq!(matrix_1x1[0].len(), 1);
        assert_eq!(matrix_1x1[0][0], FieldElement::<Stark252PrimeField>::from(1u64));

        // Test 6: Larger matrix to test parallel execution
        let rows = 10;
        let cols = 5;
        let large_matrix = generate_vandermonde_matrix(rows, cols);

        assert_eq!(large_matrix.len(), rows);
        assert_eq!(large_matrix[0].len(), cols);

        // Verify all elements in the matrix
        for i in 0..rows {
            let base = (i as u64) + 1;
            for j in 0..cols {
                let expected = FieldElement::<Stark252PrimeField>::from(base).pow(j as u64);
                assert_eq!(large_matrix[i][j], expected);
            }
        }

        // Test 7: Zero rows or columns
        let empty_matrix_1 = generate_vandermonde_matrix(0, 5);
        assert_eq!(empty_matrix_1.len(), 0);

        let empty_matrix_2 = generate_vandermonde_matrix(5, 0);
        assert_eq!(empty_matrix_2.len(), 5);
        assert_eq!(empty_matrix_2[0].len(), 0);
    }
}


// /// Multiplies a vector by a matrix and returns the result as a new vector.
// /// Computations are done over a finite field defined by the modulus.
// ///
// /// # Arguments
// ///
// /// * `vector` - The vector to multiply.
// /// * `matrix` - The matrix to be multiplied by.
// /// * `modulus` - The modulus for finite field computations.
// ///
// /// # Returns
// ///
// /// A vector that is the result of the multiplication.
// pub(crate) fn multiply_vector_matrix(vector: &Vec<i64>, matrix: &Vec<Vec<i64>>, modulus: i64) -> Vec<i64> {
//     matrix.iter().map(|row| {
//         row.iter().enumerate().fold(0, |acc, (i, &val)| {
//             (acc + val * vector[i]) % modulus
//         })
//     }).collect()
// }

// /// Computes the inner product of two vectors.
// /// The computation is carried out over a finite field defined by the modulus.
// ///
// /// # Arguments
// ///
// /// * `vec_a` - The first vector.
// /// * `vec_b` - The second vector.
// /// * `modulus` - The modulus for finite field computations.
// ///
// /// # Returns
// ///
// /// The scalar result of the inner product.
// pub(crate) fn inner_product(vec_a: &Vec<i64>, vec_b: &Vec<i64>, modulus: i64) -> i64 {
//     vec_a.iter().zip(vec_b.iter())
//         .fold(0, |acc, (&a, &b)| acc + a * b % modulus)
// }


// /// Checks if the interpolated polynomial from shares is at most of degree t in a finite field.
// ///
// /// # Arguments
// ///
// /// * `degree` - The maximum allowed degree of the polynomial.
// /// * `shares` - A vector of (x, y) coordinates representing the shares.
// /// * `modulus` - The modulus for the finite field.
// ///
// /// # Returns
// ///
// /// `true` if the interpolated polynomial is at most of degree t, `false` otherwise.
// // pub(crate) fn is_degree_t_consistent(degree: i64, shares: Vec<(i64, i64)>, modulus: i64) -> bool {
//     let coeffs = interpolate_polynomial(shares, modulus);
//     coeffs.len() as i64 - 1 <= degree
// }

// /// Computes the modular multiplicative inverse using the extended Euclidean algorithm.
// pub(crate) fn mod_inverse(a: i64, m: i64) -> i64 {
//     let (mut old_r, mut r) = (a, m);
//     let (mut old_s, mut s) = (1, 0);
//
//     while r != 0 {
//         let quotient = old_r / r;
//         let temp_r = r;
//         r = old_r - quotient * r;
//         old_r = temp_r;
//
//         let temp_s = s;
//         s = old_s - quotient * s;
//         old_s = temp_s;
//     }
//
//     old_s.rem_euclid(m)
// }
/*

/// Generates a vandermonde matrix with the specified number of rows and columns.
/// The values are computed over a finite field defined by the provided modulus.
///
/// # Arguments
///
/// * `rows` - The number of rows in the matrix.
/// * `cols` - The number of columns in the matrix.
/// * `modulus` - The modulus for finite field computations.
///
/// # Returns
///
/// A 2D vector representing the vandermonde matrix.

 */