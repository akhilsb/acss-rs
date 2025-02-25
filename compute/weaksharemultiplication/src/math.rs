pub(crate) fn matrix_vector_mul(matrix: &Vec<Vec<i64>>, vector: &Vec<i64>, modulus: i64) -> Vec<i64> {
    // Check if the matrix is empty
    assert!(!matrix.is_empty(), "Matrix cannot be empty");

    // Check if all rows in the matrix have the same length
    let row_length = matrix[0].len();
    assert!(matrix.iter().all(|row| row.len() == row_length), "All rows in the matrix must have the same length");

    // Check if the vector length matches the number of columns in the matrix
    assert_eq!(row_length, vector.len(), "Vector length must match the number of columns in the matrix");

    // Perform matrix-vector multiplication
    matrix
        .iter()
        .map(|row| {
            row.iter()
                .zip(vector.iter())
                .map(|(&a, &b)| (a * b) % modulus)
                .fold(0, |acc, x| (acc + x) % modulus)
        })
        .collect()
}

pub(crate) fn dot_product(a: &Vec<i64>, b: &Vec<i64>) -> i64 {
    // Assert that the vectors have the same length
    assert_eq!(a.len(), b.len(), "Vectors must have the same length");

    // Compute the dot product
    a.iter()
        .zip(b.iter())
        .map(|(&x, &y)| x * y)
        .sum()
}

/// Evaluates a polynomial at a given point using modular arithmetic.
///
/// # Arguments
///
/// * `coefficients` - A vector of i64 integers representing the coefficients of the polynomial,
///                    from the lowest degree term to the highest.
/// * `evaluation_point` - The point at which to evaluate the polynomial.
/// * `modulus` - Result is modulus this value.
///
/// # Returns
///
/// The result of the polynomial evaluation modulo the given modulus.
///
/// # Example
///
/// ```
/// use publicweak::protocol::evaluate_polynomial_from_coefficients_at_position;
/// let coefficients = vec![1, 2, 3];  // Represents the polynomial 1 + 2x + 3x^2
/// let evaluation_point = 15;
/// let modulus = 17;
/// let result = evaluate_polynomial_from_coefficients_at_position(coefficients, evaluation_point, modulus);
/// assert_eq!(result, 9);  // (1 + 2*5 + 3*5^2) % 1000 = 86
/// ```
pub(crate) fn evaluate_polynomial_from_coefficients_at_position(coefficients: Vec<i64>, evaluation_point: i64, modulus: i64) -> i64 {
    let mut result = 0;
    let mut x_power = 1;

    for coefficient in coefficients {
        result = (result + coefficient * x_power).rem_euclid(modulus);
        x_power = (x_power * evaluation_point).rem_euclid(modulus);
    }

    result
}

/// Checks if the interpolated polynomial from shares is at most of degree t in a finite field.
///
/// # Arguments
///
/// * `degree` - The maximum allowed degree of the polynomial.
/// * `shares` - A vector of (x, y) coordinates representing the shares.
/// * `modulus` - The modulus for the finite field.
///
/// # Returns
///
/// `true` if the interpolated polynomial is at most of degree t, `false` otherwise.
pub(crate) fn is_degree_t_consistent(degree: i64, shares: Vec<(i64, i64)>, modulus: i64) -> bool {
    let coeffs = interpolate_polynomial(shares, modulus);
    coeffs.len() as i64 - 1 <= degree
}

/// Computes the modular multiplicative inverse using the extended Euclidean algorithm.
pub(crate) fn mod_inverse(a: i64, m: i64) -> i64 {
    let (mut old_r, mut r) = (a, m);
    let (mut old_s, mut s) = (1, 0);

    while r != 0 {
        let quotient = old_r / r;
        let temp_r = r;
        r = old_r - quotient * r;
        old_r = temp_r;

        let temp_s = s;
        s = old_s - quotient * s;
        old_s = temp_s;
    }

    old_s.rem_euclid(m)
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
pub(crate) fn interpolate_polynomial(shares: Vec<(i64, i64)>, modulus: i64) -> Vec<i64> {
    let n = shares.len();
    let mut matrix = vec![vec![0i64; n + 1]; n];

    // Populate the matrix
    for (i, &(x, y)) in shares.iter().enumerate() {
        let mut x_power = 1i64;
        for j in 0..n {
            matrix[i][j] = x_power.rem_euclid(modulus);
            x_power = (x_power * x).rem_euclid(modulus);
        }
        matrix[i][n] = y.rem_euclid(modulus);
    }

    // Perform Gaussian elimination
    for i in 0..n {
        // Find pivot
        let mut pivot_row = i;
        for j in i + 1..n {
            if matrix[j][i] != 0 {
                pivot_row = j;
                break;
            }
        }

        // Swap rows if necessary
        if pivot_row != i {
            matrix.swap(i, pivot_row);
        }

        let pivot = matrix[i][i];
        let pivot_inv = mod_inverse(pivot, modulus);

        // Normalize pivot row
        for j in i..=n {
            matrix[i][j] = (matrix[i][j] * pivot_inv).rem_euclid(modulus);
        }

        // Eliminate in other rows
        for k in 0..n {
            if k != i {
                let factor = matrix[k][i];
                for j in i..=n {
                    matrix[k][j] = (matrix[k][j] - factor * matrix[i][j]).rem_euclid(modulus);
                }
            }
        }
    }

    // Extract solution
    let mut result: Vec<i64> = matrix.iter().map(|row| row[n]).collect();

    // Remove leading zero coefficients
    while result.len() > 1 && result.last() == Some(&0) {
        result.pop();
    }

    result
}

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
pub(crate) fn generate_vandermonde_matrix(rows: usize, cols: usize, modulus: i64) -> Vec<Vec<i64>> {
    (0..rows)
        .map(|i| {
            (0..cols)
                .map(|j| {
                    let base = i as i64 + 1; // Using row index + 1 as the base.
                    base.pow(j as u32).rem_euclid(modulus)
                })
                .collect()
        })
        .collect()
}

/// Multiplies a vector by a matrix and returns the result as a new vector.
/// Computations are done over a finite field defined by the modulus.
///
/// # Arguments
///
/// * `vector` - The vector to multiply.
/// * `matrix` - The matrix to be multiplied by.
/// * `modulus` - The modulus for finite field computations.
///
/// # Returns
///
/// A vector that is the result of the multiplication.
pub(crate) fn multiply_vector_matrix(vector: &Vec<i64>, matrix: &Vec<Vec<i64>>, modulus: i64) -> Vec<i64> {
    matrix.iter().map(|row| {
        row.iter().enumerate().fold(0, |acc, (i, &val)| {
            (acc + val * vector[i]) % modulus
        })
    }).collect()
}

/// Computes the inner product of two vectors.
/// The computation is carried out over a finite field defined by the modulus.
///
/// # Arguments
///
/// * `vec_a` - The first vector.
/// * `vec_b` - The second vector.
/// * `modulus` - The modulus for finite field computations.
///
/// # Returns
///
/// The scalar result of the inner product.
pub(crate) fn inner_product(vec_a: &Vec<i64>, vec_b: &Vec<i64>, modulus: i64) -> i64 {
    vec_a.iter().zip(vec_b.iter())
        .fold(0, |acc, (&a, &b)| acc + a * b % modulus)
}