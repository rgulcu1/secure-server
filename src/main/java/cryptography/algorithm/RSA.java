package cryptography.algorithm;

import util.Constants;
import util.Helper;
import cryptography.key.KeyPair;
import cryptography.key.PrivateKey;
import cryptography.key.PublicKey;

import java.math.BigInteger;
import java.security.SecureRandom;

public class RSA {


    public static KeyPair generateKeyset() {

        BigInteger p = generatePrime(Constants.PRIME_BIT_SIZE);
        BigInteger q = generatePrime(Constants.PRIME_BIT_SIZE);

        BigInteger n = p.multiply(q);

        BigInteger z = p.subtract(BigInteger.ONE).multiply(q.subtract(BigInteger.ONE));

        int randomIndex = (int)(Math.random() * Constants.firstFewPrime.size());

        BigInteger e = BigInteger.valueOf(Constants.firstFewPrime.get(randomIndex));
        BigInteger d;

        BigInteger tempNumber = new BigInteger(z.toString());
        while(true) {

            if (tempNumber.add(BigInteger.ONE).mod(e).equals(BigInteger.ZERO)) {
                d = tempNumber.add(BigInteger.ONE).divide(e);
                break;
            }

            tempNumber = tempNumber.add(z);
        }

        PublicKey publicKey = new PublicKey(n, e);
        PrivateKey privateKey = new PrivateKey(n, d);

        return new KeyPair(publicKey, privateKey);
    }

    private static BigInteger generatePrime(int bitSize) {

        BigInteger candidatePrime;
        while(true) {
            candidatePrime = generateRandomOddNumber(bitSize); // generate random odd number

            boolean firstTestPassed = lowLevelPrimeTest(candidatePrime);

            if (!firstTestPassed) continue;

            boolean secondTestPrime = millerRabinTest(candidatePrime);
            if (!secondTestPrime) continue;
            break;
        }

        return candidatePrime;
    }

    private static boolean lowLevelPrimeTest(BigInteger candidatePrime) {

        int testPrimeSize = Constants.firstFewPrime.size();

        for (int i = 0; i < testPrimeSize; i++) {

            if (candidatePrime.mod(BigInteger.valueOf(Constants.firstFewPrime.get(i))).equals(BigInteger.ZERO)) {
               return false;
            }
        }
        return true;
    }


    private static boolean millerRabinTest(BigInteger candidatePrime) {

        // Corner cases
        if (candidatePrime.compareTo(BigInteger.ONE) != 1 || candidatePrime.equals(BigInteger.valueOf(4)))
            return false;
        if (candidatePrime.compareTo(BigInteger.valueOf(3)) != 1)
            return true;

        BigInteger d = candidatePrime.subtract(BigInteger.ONE);

        while (d.mod(BigInteger.valueOf(2)).equals(BigInteger.ZERO)) d = d.divide(BigInteger.valueOf(2));

        for (int i = 0; i < Constants.MILLER_RABIN_ITERATION; i++)
            if (!checkWithMillerTest(d, candidatePrime))
                return false;

        return true;
    }

    private static boolean checkWithMillerTest(BigInteger d, BigInteger n) {

        BigInteger a = Helper.nextRandomBigInteger(n);
        BigInteger x = Helper.modForBigNumbers(a,d,n);

        if(x.equals(BigInteger.ONE) || x.equals(n.subtract(BigInteger.ONE))) return true;

        while (!d.equals(n.subtract(BigInteger.ONE))) {
            x = x.pow(2).mod(n);
            d = d.multiply(BigInteger.valueOf(2));

            if (x.equals(BigInteger.ONE))
                return false;
            if (x.equals(n.subtract(BigInteger.ONE)))
                return true;
        }

        // Return composite
        return false;
    }


    private static BigInteger generateRandomOddNumber(int bitSize) {

        StringBuilder stringBuilder = new StringBuilder();
        stringBuilder.append("1");
        SecureRandom random = new SecureRandom();

        for (int i = 1; i <bitSize-1 ; i++) {

            if (random.nextDouble() > 0.5) {
                stringBuilder.append("1");
            }else {
                stringBuilder.append("0");
            }
        }
        stringBuilder.append("1");

        String randomNumberAsBinary = stringBuilder.toString();

        return new BigInteger(randomNumberAsBinary, 2);
    }



}
