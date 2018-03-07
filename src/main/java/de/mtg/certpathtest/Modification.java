
package de.mtg.certpathtest;

public enum Modification
{

    WRONG_SIGNATURE,
    WRONG_DER_ENCODING,
    RSA_LOW_EXPONENT,
    DIFF_SIGN_ALGORITHMS,
    DUPLICATE_EXTENSION,
    UNKNOWN_SIGN_ALGORITHM,
    EMPTY_SIGNATURE;


}
