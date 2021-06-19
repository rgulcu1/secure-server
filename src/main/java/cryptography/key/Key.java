package cryptography.key;

public interface Key {

    String encrypt(String plainText);

    String decrypt(String cipherText);
}
