package cryptography.key;

public class KeyPair {

    private Key publicKey;

    private Key privateKey;


    public KeyPair(final Key publicKey, final Key privateKey) {
        this.publicKey = publicKey;
        this.privateKey = privateKey;
    }

    public Key getPublicKey() {
        return publicKey;
    }

    public Key getPrivateKey() {
        return privateKey;
    }
}
