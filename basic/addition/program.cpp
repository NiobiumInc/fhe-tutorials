#include "openfhe.h"

#ifdef NIOBIUM_COMPILER
#include "niobium/compiler.hpp"
#endif

#include <iostream>
#include <iomanip>
#include <string>


using namespace lbcrypto;

/* An example of taking two arguments as input and computing the addition.
 *
 * Run the example with the niobium client CLI as follows:
 *
 *   $ niobium run basic/addition 6.48074069840786 7.22
 *   <snip>
 *   The input is 6.48074069840786 and 7.22
 *   The answer is 13.70074069840786
 *   <snip>
 */

void add(CryptoContext<DCRTPoly> cc, Ciphertext<DCRTPoly> ct1, Ciphertext<DCRTPoly> ct2, Ciphertext<DCRTPoly>& addition) {
  addition = cc->EvalAdd(ct1, ct2);
}

int main(int argc, char** argv) {
  if (argc < 3) {
    std::cerr << "Usage: " << argv[0] << " [1st number] [2nd number]" << std::endl;
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

  double num1 = std::stod(argv[1]);
  std::cout << "The input for 1st number is " << std::fixed << std::setprecision(14) << num1 << std::endl;

  std::vector<double> x1{num1};
  Plaintext pt1 = cc->MakeCKKSPackedPlaintext(x1, 1, 0, nullptr, 1);

  Ciphertext<DCRTPoly> ct1 = cc->Encrypt(keys.publicKey, pt1);

  double num2 = std::stod(argv[2]);
  std::cout << "The input for 2nd number is " << std::fixed << std::setprecision(14) << num2 << std::endl;

  std::vector<double> x2{num2};
  Plaintext pt2 = cc->MakeCKKSPackedPlaintext(x2, 1, 0, nullptr, 1);

  Ciphertext<DCRTPoly> ct2 = cc->Encrypt(keys.publicKey, pt2);


  Ciphertext<DCRTPoly> addition;

#ifdef NIOBIUM_COMPILER
  niobium::compiler().run(add, cc, ct1, ct2, addition);
#endif

  Plaintext addPt;
  cc->Decrypt(keys.secretKey, addition, &addPt);
  addPt->SetLength(1);

  auto d = addPt->GetCKKSPackedValue()[0].real();
  std::cout << "The answer is " << std::defaultfloat << d << "." << std::endl;
}
