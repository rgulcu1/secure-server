package cryptography.key;
import lombok.Getter;
import request.PublicKeyRequestModel;
import util.Helper;

import java.math.BigInteger;

@Getter
public class PublicKey implements Key {

    private BigInteger n;

    private BigInteger e;



    public PublicKey(PublicKeyRequestModel publicKeyRequestModel) {
        this.n = new BigInteger(publicKeyRequestModel.getN(),16);
        this.e = new BigInteger(publicKeyRequestModel.getE(),16);;
    }

    public PublicKey(final BigInteger n, final BigInteger e) {
        this.n = n;
        this.e = e;
    }

    @Override
    public String encrypt(final String plainText) {

        BigInteger dataAsDecimal = new BigInteger(plainText, 16);
        BigInteger cipherAsDecimal = Helper.modForBigNumbers(dataAsDecimal, e, n);
        return cipherAsDecimal.toString(16).toUpperCase();
    }

    @Override
    public String decrypt(final String cipherText) {
        BigInteger cipherAsDecimal = new BigInteger(cipherText, 16);
        BigInteger plainAsDecimal = Helper.modForBigNumbers(cipherAsDecimal, e, n);
        return plainAsDecimal.toString(16).toUpperCase();
    }

    public Boolean verifyDigitalSignature(String digitalSignature, String data){

        String decryptedMessage = decrypt(digitalSignature);

        System.out.print("Decrypt digital signature with Ka+. The result is : ");
        System.out.println(decryptedMessage);

        System.out.print("Apply hash to message and compare. Hashed message: ");
        String hashedData = Helper.hashWithSHA256(data);;
        System.out.println(hashedData);

        if (decryptedMessage.equals(hashedData)) {
            System.out.println("These are equal. Digital signature verified.");
            return true;
        }else{
            System.out.println("These are not equal. The digital signature could not be verified");
            return false;
        }

    }
}
