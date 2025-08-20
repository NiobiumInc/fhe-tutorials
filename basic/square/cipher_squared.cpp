#include "openfhe.h"

#ifdef NIOBIUM_COMPILER
#include "niobium/compiler.hpp"
#endif

#include <iostream>
#include <iomanip>
#include <string>

using namespace lbcrypto;

/* An example of taking an argument as input and computing the square.
 *
 * Run the example with the niobium client CLI as follows:
 *
 *   $ niobium run examples/cipher_squared.cpp 6.48074069840786
 *   <snip>
 *   The input is 6.48074069840786
 *   The answer is 42.
 *   <snip>
 */

void multiply(CryptoContext<DCRTPoly> cc, Ciphertext<DCRTPoly> ct, Ciphertext<DCRTPoly>& sq) {
  sq = cc->EvalSquare(ct);
}

int main(int argc, char** argv) {
  if (argc < 4) {
    std::cerr << "Usage: " << argv[0] << " <unused> <unused> [a number]" << std::endl;
    return 1;
  }

  CCParams<CryptoContextCKKSRNS> parameters;
  parameters.SetSecurityLevel(HEStd_192_classic);
  parameters.SetRingDim(1 << 16);
  parameters.SetMultiplicativeDepth(2);
  parameters.SetScalingModSize(59);

  CryptoContext<DCRTPoly> cc = GenCryptoContext(parameters);
  cc->Enable(PKE);
  cc->Enable(LEVELEDSHE);
  cc->Enable(ADVANCEDSHE);

  auto keys = cc->KeyGen();
  cc->EvalMultKeyGen(keys.secretKey);

  double n = std::stod(argv[3]);
  std::cout << "The input is " << std::fixed << std::setprecision(14) << n << std::endl;

  std::vector<double> x{n};
  Plaintext pt = cc->MakeCKKSPackedPlaintext(x, 1, 0, nullptr, 1);

  Ciphertext<DCRTPoly> ct = cc->Encrypt(keys.publicKey, pt);
  Ciphertext<DCRTPoly> sq;

#ifdef NIOBIUM_COMPILER
  niobium::compiler().run(multiply, cc, ct, sq);
#endif

  Plaintext sqPt;
  cc->Decrypt(keys.secretKey, sq, &sqPt);
  sqPt->SetLength(1);

  auto d = sqPt->GetCKKSPackedValue()[0].real();
  std::cout << "The answer is " << std::defaultfloat << d << "." << std::endl;
}
