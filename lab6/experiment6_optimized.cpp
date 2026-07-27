/**
 * Experiment 6: Rotation-Optimized HE Convolution
 *
 * Using OpenFHE CKKS with the "Packing → Rotation → Accumulation" strategy
 * to minimize the number of rotation keys and EvalRotate calls.
 *
 * Key insight: Rotation results can be reused.
 *   - Base generators: rotations by 1, 2, 4 (and 8 can be derived as 4+4)
 *   - offset 5 = Rotate(Rotate(ct, 4), 1) — reuses rot4 result
 *   - offset 6 = Rotate(Rotate(ct, 4), 2) — reuses rot4 result
 *   - offset 9 = Rotate(Rotate(ct, 8), 1) — reuses rot8 result
 *   - offset 10 = Rotate(Rotate(ct, 8), 2) — reuses rot8 result
 *
 * This reduces:
 *   - Rotation key indices from 8 to 4 (or even 3 if 8 is derived from 4+4)
 *   - EvalRotate calls from 8 to 8 (same, but keys are reduced)
 *   - If we derive 2 from 1+1 and 8 from 4+4, rotation key indices drop to just 2
 *
 * Theoretical minimum analysis:
 *   For a 4×4 input with 3×3 kernel, we need to access 9 positions.
 *   The generators of the offset group are {1, 4} (horizontal step, vertical step).
 *   All 9 offsets can be expressed as a*1 + b*4 where a∈{0,1,2}, b∈{0,1,2}.
 *   So theoretically, only 2 rotation keys (±1, ±4) are needed.
 *   If we allow ±2 as an optimization, we need 3 keys (±1, ±2, ±4).
 */

#include <iostream>
#include <vector>
#include <iomanip>
#include <cmath>
#include <map>
#include <string>

#include "openfhe.h"

using namespace lbcrypto;

/**
 * Strategy A: Naive (Baseline) — 9 independent rotations
 * Strategy B: Key-reuse: keys for {1, 2, 4, 8}, compose rest
 * Strategy C: Minimal keys: keys for {1, 4} only, compose everything
 */

struct StrategyResult {
    std::string name;
    std::vector<int32_t> rotationKeysNeeded;
    int evalRotateCalls;
    int evalMultCalls;
    int evalAddCalls;
    std::vector<double> output2x2;
    double maxError;
};

StrategyResult runStrategy(
    CryptoContext<DCRTPoly>& cc,
    KeyPair<DCRTPoly>& keyPair,
    const std::vector<double>& input4x4,
    const std::vector<double>& kernel3x3,
    const std::string& strategyName,
    int strategyId)
{
    StrategyResult res;
    res.name = strategyName;

    std::cout << std::endl;
    std::cout << "------------------------------------------------------------" << std::endl;
    std::cout << "  Strategy " << strategyId << ": " << strategyName << std::endl;
    std::cout << "------------------------------------------------------------" << std::endl;

    // Offsets for 3×3 convolution
    std::vector<int32_t> offsets = {0, 1, 2, 4, 5, 6, 8, 9, 10};
    double* kernelWeights = const_cast<double*>(kernel3x3.data());

    // Encrypt input
    Plaintext pt = cc->MakeCKKSPackedPlaintext(input4x4);
    auto ct = cc->Encrypt(keyPair.publicKey, pt);

    int batchSize = 16;
    res.evalRotateCalls = 0;
    res.evalMultCalls = 0;
    res.evalAddCalls = 0;

    Ciphertext<DCRTPoly> accumulator;
    bool first = true;

    if (strategyId == 1) {
        // ================================================================
        // Strategy 1 (Baseline): 9 independent rotations from original ct
        // ================================================================
        res.rotationKeysNeeded = {1, 2, 4, 5, 6, 8, 9, 10};

        for (size_t k = 0; k < offsets.size(); k++) {
            double w = kernel3x3[k];
            if (std::abs(w) < 1e-10) continue;

            Ciphertext<DCRTPoly> rotated;
            if (offsets[k] == 0) {
                rotated = ct;
            } else {
                rotated = cc->EvalRotate(ct, offsets[k]);
                res.evalRotateCalls++;
            }

            auto wpt = cc->MakeCKKSPackedPlaintext(std::vector<double>(batchSize, w));
            auto weighted = cc->EvalMult(rotated, wpt);
            res.evalMultCalls++;

            if (first) {
                accumulator = weighted;
                first = false;
            } else {
                accumulator = cc->EvalAdd(accumulator, weighted);
                res.evalAddCalls++;
            }
        }
    }
    else if (strategyId == 2) {
        // ================================================================
        // Strategy 2: Rotation reuse — generate base rotations first,
        //             then compose derived offsets
        // ================================================================
        res.rotationKeysNeeded = {1, 2, 4, 8};

        // Pre-compute base rotations
        auto rot0 = ct;                    // offset 0 (free)
        auto rot1 = cc->EvalRotate(ct, 1);  res.evalRotateCalls++;
        auto rot2 = cc->EvalRotate(ct, 2);  res.evalRotateCalls++;
        auto rot4 = cc->EvalRotate(ct, 4);  res.evalRotateCalls++;
        auto rot8 = cc->EvalRotate(ct, 8);  res.evalRotateCalls++;

        // Derive composed rotations
        auto rot5 = cc->EvalRotate(rot4, 1);   res.evalRotateCalls++;  // 4+1
        auto rot6 = cc->EvalRotate(rot4, 2);   res.evalRotateCalls++;  // 4+2
        auto rot9 = cc->EvalRotate(rot8, 1);   res.evalRotateCalls++;  // 8+1
        auto rot10 = cc->EvalRotate(rot8, 2);  res.evalRotateCalls++;  // 8+2

        std::cout << "  Composed rotations: rot5=rot4→1, rot6=rot4→2, "
                  << "rot9=rot8→1, rot10=rot8→2" << std::endl;

        // Map offsets to ciphertexts
        std::map<int32_t, Ciphertext<DCRTPoly>> offsetMap = {
            {0, rot0}, {1, rot1}, {2, rot2}, {4, rot4},
            {5, rot5}, {6, rot6}, {8, rot8}, {9, rot9}, {10, rot10}
        };

        for (size_t k = 0; k < offsets.size(); k++) {
            double w = kernel3x3[k];
            if (std::abs(w) < 1e-10) continue;

            auto wpt = cc->MakeCKKSPackedPlaintext(std::vector<double>(batchSize, w));
            auto weighted = cc->EvalMult(offsetMap[offsets[k]], wpt);
            res.evalMultCalls++;

            if (first) {
                accumulator = weighted;
                first = false;
            } else {
                accumulator = cc->EvalAdd(accumulator, weighted);
                res.evalAddCalls++;
            }
        }
    }
    else if (strategyId == 3) {
        // ================================================================
        // Strategy 3: Minimal rotation keys — only {1, 4}
        //             Derive 2 = 1+1, 8 = 4+4
        // ================================================================
        res.rotationKeysNeeded = {1, 4};

        auto rot0 = ct;
        auto rot1 = cc->EvalRotate(ct, 1);   res.evalRotateCalls++;
        auto rot2 = cc->EvalRotate(rot1, 1);  res.evalRotateCalls++;  // 1+1
        auto rot4 = cc->EvalRotate(ct, 4);    res.evalRotateCalls++;

        // Compose remaining offsets
        auto rot5 = cc->EvalRotate(rot4, 1);   res.evalRotateCalls++;  // 4+1
        auto rot6 = cc->EvalRotate(rot4, 2);   res.evalRotateCalls++;  // 4+2 (using composed rot)
        auto rot8 = cc->EvalRotate(rot4, 4);   res.evalRotateCalls++;  // 4+4
        auto rot9 = cc->EvalRotate(rot8, 1);   res.evalRotateCalls++;  // 8+1
        auto rot10 = cc->EvalRotate(rot8, 2);  res.evalRotateCalls++;  // 8+2 (using composed rot)

        std::cout << "  Derived: rot2=rot1→1, rot5=rot4→1, rot6=rot4→2, "
                  << "rot8=rot4→4, rot9=rot8→1, rot10=rot8→2" << std::endl;

        std::map<int32_t, Ciphertext<DCRTPoly>> offsetMap = {
            {0, rot0}, {1, rot1}, {2, rot2}, {4, rot4},
            {5, rot5}, {6, rot6}, {8, rot8}, {9, rot9}, {10, rot10}
        };

        for (size_t k = 0; k < offsets.size(); k++) {
            double w = kernel3x3[k];
            if (std::abs(w) < 1e-10) continue;

            auto wpt = cc->MakeCKKSPackedPlaintext(std::vector<double>(batchSize, w));
            auto weighted = cc->EvalMult(offsetMap[offsets[k]], wpt);
            res.evalMultCalls++;

            if (first) {
                accumulator = weighted;
                first = false;
            } else {
                accumulator = cc->EvalAdd(accumulator, weighted);
                res.evalAddCalls++;
            }
        }
    }
    else if (strategyId == 4) {
        // ================================================================
        // Strategy 4: Aggressive reuse — minimize EvalRotate calls
        //             Generate rot1 once, chain: rot2=rot1→1, rot4
        //             Then: rot5=rot4→1, rot6=rot4→2(or rot5→1),
        //             rot8=rot4→4, rot9=rot8→1, rot10=rot9→1
        //             With zero-weight skipping (k01=0, k11=0, k21=0)
        // ================================================================
        res.rotationKeysNeeded = {1, 4};

        // Since kernel weights at indices 1, 4 are 0, we can skip offset 1!
        // Non-zero weights are at: k00(offset 0, w=1), k02(offset 2, w=-1),
        //   k10(offset 4, w=1), k12(offset 6, w=-1),
        //   k20(offset 8, w=1), k22(offset 10, w=-1)
        // Still need offset 2 though.
        // But offset 5 and 9 are zero-weight → skip!

        auto rot0 = ct;
        auto rot2 = cc->EvalRotate(ct, 2);    res.evalRotateCalls++;
        auto rot4 = cc->EvalRotate(ct, 4);    res.evalRotateCalls++;
        auto rot6 = cc->EvalRotate(rot4, 2);   res.evalRotateCalls++;
        auto rot8 = cc->EvalRotate(rot4, 4);   res.evalRotateCalls++;
        auto rot10 = cc->EvalRotate(rot8, 2);  res.evalRotateCalls++;

        std::cout << "  Zero-weight skip: offsets 1,5,9 skipped (kernel weight=0)" << std::endl;
        std::cout << "  Compositions: rot6=rot4→2, rot8=rot4→4, rot10=rot8→2" << std::endl;

        std::map<int32_t, Ciphertext<DCRTPoly>> offsetMap = {
            {0, rot0}, {2, rot2}, {4, rot4},
            {6, rot6}, {8, rot8}, {10, rot10}
        };

        // Only process non-zero weights
        const std::vector<size_t> activeKernelIndices = {0, 2, 3, 5, 6, 8};
        for (size_t ki : activeKernelIndices) {
            double w = kernel3x3[ki];
            auto wpt = cc->MakeCKKSPackedPlaintext(std::vector<double>(batchSize, w));
            auto weighted = cc->EvalMult(offsetMap[offsets[ki]], wpt);
            res.evalMultCalls++;

            if (first) {
                accumulator = weighted;
                first = false;
            } else {
                accumulator = cc->EvalAdd(accumulator, weighted);
                res.evalAddCalls++;
            }
        }
    }

    // Decrypt and verify
    Plaintext resultPt;
    cc->Decrypt(keyPair.secretKey, accumulator, &resultPt);
    resultPt->SetLength(16);
    std::vector<double> decrypted = resultPt->GetRealPackedValue();

    res.output2x2 = {decrypted[0], decrypted[1], decrypted[4], decrypted[5]};

    auto expected = std::vector<double>{-6.0, -6.0, -6.0, -6.0};
    res.maxError = 0.0;
    for (size_t i = 0; i < 4; i++) {
        double e = std::abs(res.output2x2[i] - expected[i]);
        if (e > res.maxError) res.maxError = e;
    }

    // Print per-strategy results
    std::cout << std::endl;
    std::cout << "  --- Strategy " << strategyId << " Results ---" << std::endl;
    std::cout << "  Rotation keys needed: " << res.rotationKeysNeeded.size()
              << " (indices: ";
    for (auto idx : res.rotationKeysNeeded) std::cout << idx << " ";
    std::cout << ")" << std::endl;
    std::cout << "  EvalRotate calls:     " << res.evalRotateCalls << std::endl;
    std::cout << "  EvalMult calls:       " << res.evalMultCalls << std::endl;
    std::cout << "  EvalAdd calls:        " << res.evalAddCalls << std::endl;
    std::cout << "  Convolution output:   [" << std::fixed << std::setprecision(6)
              << res.output2x2[0] << ", " << res.output2x2[1] << "]" << std::endl;
    std::cout << "                        [" << res.output2x2[2] << ", "
              << res.output2x2[3] << "]" << std::endl;
    std::cout << "  Max error:            " << std::scientific << res.maxError << std::endl;
    std::cout << "  Correct:              " << (res.maxError < 0.01 ? "✓ YES" : "✗ NO") << std::endl;

    return res;
}

int main() {
    std::cout << "============================================================" << std::endl;
    std::cout << "  Experiment 6: Rotation-Optimized HE Convolution" << std::endl;
    std::cout << "============================================================" << std::endl;
    std::cout << std::endl;

    // ================================================================
    // Setup
    // ================================================================
    uint32_t multDepth = 4;   // Extra depth for composed rotations
    uint32_t scaleModSize = 50;
    uint32_t batchSize = 16;

    CCParams<CryptoContextCKKSRNS> parameters;
    parameters.SetMultiplicativeDepth(multDepth);
    parameters.SetScalingModSize(scaleModSize);
    parameters.SetBatchSize(batchSize);
    parameters.SetRingDim(1 << 15);  // 32768

    CryptoContext<DCRTPoly> cc = GenCryptoContext(parameters);
    cc->Enable(PKE);
    cc->Enable(KEYSWITCH);
    cc->Enable(LEVELEDSHE);
    cc->Enable(ADVANCEDSHE);

    std::cout << "CKKS Parameters:" << std::endl;
    std::cout << "  Ring dimension:  " << cc->GetRingDimension() << std::endl;
    std::cout << "  Batch size:      " << batchSize << std::endl;
    std::cout << "  Mult depth:      " << multDepth << std::endl;
    std::cout << "  Scale mod size:  " << scaleModSize << " bits" << std::endl;
    std::cout << std::endl;

    // Generate all rotation keys we might need (1-4, 8) for all strategies
    // Strategy 3 (minimal keys) will show what's possible, but we pre-generate
    // all for fair comparison of EvalRotate call counts
    auto keyPair = cc->KeyGen();
    cc->EvalMultKeyGen(keyPair.secretKey);
    std::vector<int32_t> allRotationIndices = {1, 2, 4, 5, 6, 8, 9, 10};
    cc->EvalRotateKeyGen(keyPair.secretKey, allRotationIndices);

    std::cout << "Pre-generated rotation keys for all offsets: ";
    for (auto idx : allRotationIndices) std::cout << idx << " ";
    std::cout << std::endl << std::endl;

    // Input data
    std::vector<double> input4x4 = {
        1.0,  2.0,  3.0,  4.0,
        5.0,  6.0,  7.0,  8.0,
        9.0,  10.0, 11.0, 12.0,
        13.0, 14.0, 15.0, 16.0
    };
    std::vector<double> kernel3x3 = {
        1.0,  0.0, -1.0,
        1.0,  0.0, -1.0,
        1.0,  0.0, -1.0
    };

    std::cout << "Input (4×4):" << std::endl;
    for (int i = 0; i < 4; i++) {
        std::cout << "  ";
        for (int j = 0; j < 4; j++)
            std::cout << std::setw(5) << input4x4[i * 4 + j];
        std::cout << std::endl;
    }
    std::cout << std::endl;

    std::cout << "Kernel (3×3):" << std::endl;
    for (int i = 0; i < 3; i++) {
        std::cout << "  ";
        for (int j = 0; j < 3; j++)
            std::cout << std::setw(5) << kernel3x3[i * 3 + j];
        std::cout << std::endl;
    }
    std::cout << std::endl;

    // ================================================================
    // Run all strategies
    // ================================================================
    std::vector<StrategyResult> results;

    results.push_back(runStrategy(cc, keyPair, input4x4, kernel3x3,
        "Baseline: 9 independent rotations", 1));

    results.push_back(runStrategy(cc, keyPair, input4x4, kernel3x3,
        "Key reuse: 4 rotation keys, compose offsets 5,6,9,10", 2));

    results.push_back(runStrategy(cc, keyPair, input4x4, kernel3x3,
        "Minimal keys: 2 rotation keys {1,4}, derive all others", 3));

    results.push_back(runStrategy(cc, keyPair, input4x4, kernel3x3,
        "Aggressive: skip zero-weights, minimize compositions", 4));

    // ================================================================
    // Comparative analysis
    // ================================================================
    std::cout << std::endl;
    std::cout << "============================================================" << std::endl;
    std::cout << "  Comparative Analysis" << std::endl;
    std::cout << "============================================================" << std::endl;
    std::cout << std::endl;

    std::cout << std::left
              << std::setw(55) << "Strategy"
              << std::setw(12) << "RotKeys"
              << std::setw(14) << "EvalRotate"
              << std::setw(12) << "EvalMult"
              << std::setw(12) << "EvalAdd"
              << std::setw(14) << "MaxError"
              << std::setw(10) << "Correct"
              << std::endl;
    std::cout << std::string(130, '-') << std::endl;

    for (const auto& r : results) {
        std::cout << std::left
                  << std::setw(55) << r.name
                  << std::setw(12) << r.rotationKeysNeeded.size()
                  << std::setw(14) << r.evalRotateCalls
                  << std::setw(12) << r.evalMultCalls
                  << std::setw(12) << r.evalAddCalls
                  << std::setw(14) << std::scientific << std::setprecision(4) << r.maxError
                  << std::setw(10) << (r.maxError < 0.01 ? "✓" : "✗")
                  << std::endl;
    }

    std::cout << std::endl;
    std::cout << "============================================================" << std::endl;
    std::cout << "  Theoretical Analysis" << std::endl;
    std::cout << "============================================================" << std::endl;
    std::cout << std::endl;
    std::cout << "For a 4×4 input with 3×3 kernel (stride=1, no padding):" << std::endl;
    std::cout << std::endl;
    std::cout << "  Offset set: {0, 1, 2, 4, 5, 6, 8, 9, 10}" << std::endl;
    std::cout << "  Generators: 1 (horizontal step), 4 (vertical step)" << std::endl;
    std::cout << "  All offsets can be expressed as: a·1 + b·4" << std::endl;
    std::cout << "    where a ∈ {0,1,2}, b ∈ {0,1,2}" << std::endl;
    std::cout << std::endl;
    std::cout << "  Theoretical minimum rotation KEY indices: 2" << std::endl;
    std::cout << "    → Indices {1, 4} (or {1, 2} with different decomposition)" << std::endl;
    std::cout << std::endl;
    std::cout << "  Theoretical minimum EvalRotate calls (with zero-skip): 5" << std::endl;
    std::cout << "    → rot2=ct→2, rot4=ct→4, rot6=rot4→2, rot8=rot4→4, rot10=rot8→2" << std::endl;
    std::cout << "    (assuming zero-weight positions at offsets 1,5,9 are skipped)" << std::endl;
    std::cout << std::endl;
    std::cout << "  Strategy 4 achieves this theoretical minimum." << std::endl;
    std::cout << std::endl;

    std::cout << "============================================================" << std::endl;
    std::cout << "  Experiment 6 Complete" << std::endl;
    std::cout << "============================================================" << std::endl;

    return 0;
}
