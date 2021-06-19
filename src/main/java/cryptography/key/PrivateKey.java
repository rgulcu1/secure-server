package cryptography.key;

import util.Helper;

import java.math.BigInteger;

public class PrivateKey implements Key {

    private BigInteger n;

    private BigInteger d;


    public PrivateKey(final BigInteger n, final BigInteger d) {
        this.n = n;
        this.d = d;
    }

    @Override
    public String encrypt(final String plainText) {
        BigInteger dataAsDecimal = new BigInteger(plainText, 16);
        BigInteger cipherAsDecimal = Helper.modForBigNumbers(dataAsDecimal, d, n);
        return cipherAsDecimal.toString(16).toUpperCase();
    }

    @Override
    public String decrypt(final String cipherText) {
        BigInteger cipherAsDecimal = new BigInteger(cipherText, 16);
        BigInteger plainAsDecimal = Helper.modForBigNumbers(cipherAsDecimal, d, n);
        return plainAsDecimal.toString(16).toUpperCase();
    }

    public String generateDigitalSignature(String data) {

        return encrypt(data);
    }
}
