/**
 * Experiment 5: Homomorphic Encryption Convolution (Baseline)
 *
 * Using OpenFHE CKKS to implement a 4×4 input, 3×3 kernel convolution
 * (stride=1, no padding) with 9 direct rotations.
 *
 * Input (4×4):          Kernel (3×3):       Output (2×2):
 *   1  2  3  4           1  0 -1              -6  -6
 *   5  6  7  8           1  0 -1              -6  -6
 *   9 10 11 12           1  0 -1
 *  13 14 15 16
 */

#include <iostream>
#include <vector>
#include <iomanip>
#include <cmath>

#include "openfhe.h"

using namespace lbcrypto;

int main() {
    std::cout << "============================================================" << std::endl;
    std::cout << "  Experiment 5: Baseline HE Convolution (OpenFHE CKKS)" << std::endl;
    std::cout << "============================================================" << std::endl;
    std::cout << std::endl;

    // ================================================================
    // Step 1: Set up CKKS CryptoContext
    // ================================================================
    std::cout << "[Step 1] Setting up CKKS CryptoContext..." << std::endl;

    // For this convolution, we need enough depth:
    // - 9 multiplications (with weights) accumulated via addition
    // - Rotations and additions don't consume depth
    // - We need multiplicative depth >= 1 (one level for the mults)
    // - But for precision, we use a few more levels
    uint32_t multDepth = 3;
    uint32_t scaleModSize = 50;
    uint32_t batchSize = 16;  // 4×4 matrix packed into 16 slots

    CCParams<CryptoContextCKKSRNS> parameters;
    parameters.SetMultiplicativeDepth(multDepth);
    parameters.SetScalingModSize(scaleModSize);
    parameters.SetBatchSize(batchSize);
    // Enable rotation with a reasonable ring dimension
    parameters.SetRingDim(1 << 15);  // 32768 - sufficient for 16 batch + rotations

    CryptoContext<DCRTPoly> cc = GenCryptoContext(parameters);

    // Enable required features
    cc->Enable(PKE);
    cc->Enable(KEYSWITCH);
    cc->Enable(LEVELEDSHE);
    cc->Enable(ADVANCEDSHE);

    std::cout << "  Ring dimension: " << cc->GetRingDimension() << std::endl;
    std::cout << "  Batch size:     " << batchSize << std::endl;
    std::cout << "  Mult depth:     " << multDepth << std::endl;
    std::cout << "  Scale mod size: " << scaleModSize << " bits" << std::endl;
    std::cout << std::endl;

    // ================================================================
    // Step 2: Generate keys
    // ================================================================
    std::cout << "[Step 2] Generating keys..." << std::endl;

    auto keyPair = cc->KeyGen();

    // Generate multiplication key
    cc->EvalMultKeyGen(keyPair.secretKey);

    // Generate rotation keys for all 9 offsets
    // Offsets needed: 0, ±1, ±2, ±4, ±5, ±6, ±8, ±9, ±10
    // (0 doesn't need a key, but we list it for completeness)
    std::vector<int32_t> rotationIndices = {1, 2, 4, 5, 6, 8, 9, 10};
    cc->EvalRotateKeyGen(keyPair.secretKey, rotationIndices);

    std::cout << "  Rotation keys generated for indices: ";
    for (auto idx : rotationIndices) {
        std::cout << idx << " ";
    }
    std::cout << std::endl << std::endl;

    // ================================================================
    // Step 3: Prepare input data
    // ================================================================
    std::cout << "[Step 3] Preparing input data..." << std::endl;

    // 4×4 input matrix (row-major packing into 16 slots)
    std::vector<double> input4x4 = {
        1.0,  2.0,  3.0,  4.0,
        5.0,  6.0,  7.0,  8.0,
        9.0,  10.0, 11.0, 12.0,
        13.0, 14.0, 15.0, 16.0
    };

    // 3×3 convolution kernel
    std::vector<double> kernel3x3 = {
        1.0,  0.0, -1.0,
        1.0,  0.0, -1.0,
        1.0,  0.0, -1.0
    };

    // Offsets for 3×3 convolution on row-major packed 4×4 input
    // Each offset maps to a kernel position:
    //   kernel[i][j] → offset = i*4 + j
    std::vector<int32_t> offsets = {0, 1, 2, 4, 5, 6, 8, 9, 10};

    // Display input matrix
    std::cout << "  Input (4×4):" << std::endl;
    for (int i = 0; i < 4; i++) {
        std::cout << "    ";
        for (int j = 0; j < 4; j++) {
            std::cout << std::setw(4) << input4x4[i * 4 + j] << " ";
        }
        std::cout << std::endl;
    }
    std::cout << std::endl;

    // Display kernel
    std::cout << "  Kernel (3×3):" << std::endl;
    for (int i = 0; i < 3; i++) {
        std::cout << "    ";
        for (int j = 0; j < 3; j++) {
            std::cout << std::setw(4) << kernel3x3[i * 3 + j] << " ";
        }
        std::cout << std::endl;
    }
    std::cout << std::endl;

    // ================================================================
    // Step 4: Encrypt the input
    // ================================================================
    std::cout << "[Step 4] Packing and encrypting input..." << std::endl;

    Plaintext plaintextInput = cc->MakeCKKSPackedPlaintext(input4x4);
    auto ciphertextInput = cc->Encrypt(keyPair.publicKey, plaintextInput);

    std::cout << "  Input packed into " << batchSize << " slots and encrypted." << std::endl;
    std::cout << std::endl;

    // ================================================================
    // Step 5: Homomorphic convolution (9 rotations + 9 mults + 8 adds)
    // ================================================================
    std::cout << "[Step 5] Performing homomorphic convolution..." << std::endl;
    std::cout << "  Strategy: 9 direct rotations, each multiplied by kernel weight, then accumulated." << std::endl;
    std::cout << std::endl;

    Ciphertext<DCRTPoly> result;
    bool first = true;
    int rotationCount = 0;
    int multCount = 0;
    int addCount = 0;

    for (size_t k = 0; k < offsets.size(); k++) {
        int32_t offset = offsets[k];
        double weight = kernel3x3[k];

        if (std::abs(weight) < 1e-10) {
            std::cout << "  Kernel[" << k / 3 << "][" << k % 3
                      << "] weight=" << weight << " → skipping (zero weight)"
                      << std::endl;
            continue;  // Skip zero weights to save computation
        }

        std::cout << "  Kernel[" << k / 3 << "][" << k % 3
                  << "] offset=" << offset << ", weight=" << weight;

        // Rotate the ciphertext by the offset
        Ciphertext<DCRTPoly> rotated;
        if (offset == 0) {
            rotated = ciphertextInput;
            std::cout << " → no rotation needed";
        } else {
            rotated = cc->EvalRotate(ciphertextInput, offset);
            rotationCount++;
            std::cout << " → rotated";
        }

        // Multiply by kernel weight
        Plaintext weightPlaintext = cc->MakeCKKSPackedPlaintext(
            std::vector<double>(batchSize, weight));
        auto weighted = cc->EvalMult(rotated, weightPlaintext);
        multCount++;
        std::cout << ", multiplied";

        // Accumulate
        if (first) {
            result = weighted;
            first = false;
        } else {
            result = cc->EvalAdd(result, weighted);
            addCount++;
            std::cout << ", added to accumulator";
        }
        std::cout << std::endl;
    }

    std::cout << std::endl;
    std::cout << "  Operation counts (baseline):" << std::endl;
    std::cout << "    Rotations:     " << rotationCount << std::endl;
    std::cout << "    Multiplications: " << multCount << std::endl;
    std::cout << "    Additions:       " << addCount << std::endl;
    std::cout << std::endl;

    // ================================================================
    // Step 6: Decrypt and verify
    // ================================================================
    std::cout << "[Step 6] Decrypting and verifying..." << std::endl;

    Plaintext plaintextResult;
    cc->Decrypt(keyPair.secretKey, result, &plaintextResult);
    plaintextResult->SetLength(batchSize);
    std::vector<double> decryptedResult = plaintextResult->GetRealPackedValue();

    std::cout << "  Decrypted result (first 16 slots):" << std::endl;
    std::cout << "    ";
    for (int i = 0; i < batchSize; i++) {
        std::cout << std::fixed << std::setprecision(4) << std::setw(10) << decryptedResult[i];
        if ((i + 1) % 4 == 0 && i < batchSize - 1)
            std::cout << std::endl << "    ";
    }
    std::cout << std::endl << std::endl;

    // Extract the 2×2 convolution output (positions 0, 1, 4, 5)
    std::cout << "  Extracted 2×2 convolution output:" << std::endl;
    std::cout << "    [" << std::fixed << std::setprecision(6)
              << decryptedResult[0] << ", " << decryptedResult[1] << "]" << std::endl;
    std::cout << "    [" << std::fixed << std::setprecision(6)
              << decryptedResult[4] << ", " << decryptedResult[5] << "]" << std::endl;
    std::cout << std::endl;

    // Expected output
    std::vector<double> expected = {-6.0, -6.0, -6.0, -6.0};
    std::vector<double> actual2x2 = {
        decryptedResult[0], decryptedResult[1],
        decryptedResult[4], decryptedResult[5]
    };

    std::cout << "  Expected output:" << std::endl;
    std::cout << "    [-6.0, -6.0]" << std::endl;
    std::cout << "    [-6.0, -6.0]" << std::endl;
    std::cout << std::endl;

    // ================================================================
    // Step 7: Verification
    // ================================================================
    std::cout << "[Step 7] Verification..." << std::endl;

    bool correct = true;
    double maxError = 0.0;
    for (size_t i = 0; i < 4; i++) {
        double error = std::abs(actual2x2[i] - expected[i]);
        if (error > maxError) maxError = error;
        if (error > 0.01) correct = false;
    }

    std::cout << "  Max absolute error: " << std::scientific << maxError << std::endl;
    if (correct) {
        std::cout << "  ✓ RESULT CORRECT! HE convolution matches plaintext convolution." << std::endl;
    } else {
        std::cout << "  ✗ RESULT INCORRECT! Error exceeds tolerance." << std::endl;
        return 1;
    }
    std::cout << std::endl;

    std::cout << "============================================================" << std::endl;
    std::cout << "  Experiment 5 Complete" << std::endl;
    std::cout << "============================================================" << std::endl;

    return 0;
}
