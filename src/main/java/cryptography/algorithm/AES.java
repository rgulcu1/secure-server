package cryptography.algorithm;

import cryptography.key.SymmetricKey;
import util.Helper;

import java.math.BigInteger;
import java.security.SecureRandom;
import java.util.*;

import static util.Constants.*;

public class AES {

    private static String[][] IV = new String[4][4];

    private static String[] nonce;

    public static String[] streamCipherEncryption(String[] plainText, SymmetricKey key, Method streamMethod) {

        switch (streamMethod) {
            case CBC:
                return CBCStreamCipherEncryption(plainText, key);
            case CTR:
                return CTRStreamCipherEncryption(plainText, key);
            default:
                return CBCStreamCipherEncryption(plainText, key);
        }
    }

    private static String[] CBCStreamCipherEncryption(String[] plainText, SymmetricKey key) {

        generateInitializationVector();
        String[][] block = new String[4][4];
        Helper.deepCopy2DArray(block, IV);
        String[] cipherText = new String[plainText.length];
        String[] IVconcatCipher = Helper.concatenateArrays(Helper.unrollStringArray(IV),cipherText);


        int totalCycle = plainText.length / 16;
        int index = 0;
        for (int i = 0; i < totalCycle; i++) {
            for (int j = 0; j < 4; j++) {
                for (int k = 0; k < 4; k++) {
                    String result = Helper.hexXOR(IVconcatCipher[index], plainText[index]);
                    block[k][j] = result;
                    index++;
                }
            }
            blockCipherEncryption(block, key);

            for (int j = 0; j < 4; j++) {
                for (int k = 0; k < 4; k++) {
                    cipherText[(i<<4)+(j<<2) + k] =  block[k][j];
                    IVconcatCipher[(i<<4) + (j<<2) + k + 16] = block[k][j];
                }
            }
        }
        int uncryptedPartLength = plainText.length - index;
        while (uncryptedPartLength > 0) {
            cipherText[index] = plainText[index];
            uncryptedPartLength--;
            index++;
        }
        return cipherText;
    }

    private static String[] CTRStreamCipherEncryption(String[] plainText, SymmetricKey key) {

        generateNonce(plainText.length);
        BigInteger maxValueFor8Byte = new BigInteger("FFFFFFFFFFFFFFFF", 16);
        BigInteger counter = BigInteger.ZERO;
        String[] cipherText = new String[plainText.length];
        ArrayList<BigInteger> counterList = new ArrayList<>();

        int totalCycle = plainText.length / 16;

        for (int i = 0; i <totalCycle ; i++) {
            counterList.add(counter);
            counter=counter.add(BigInteger.ONE).mod(maxValueFor8Byte);
        }

        counterList.parallelStream().forEach(cnt -> {
            String[][] block = generateBlockForCTR(cnt);
            blockCipherEncryption(block, key);
            int i = cnt.intValue();
            for (int j = 0; j < 4; j++) {
                for (int k = 0; k < 4; k++) {
                    int index = (i<<4) + (j<<2) + k;
                    String result = Helper.hexXOR(block[k][j], plainText[index]);
                    cipherText[index] = result;
                }
            }
        });

        for (int i = plainText.length - 16; i < plainText.length; i++) {

            if(cipherText[i] == null) cipherText[i] = plainText[i];
        }

        return cipherText;
    }

    public static String[] streamCipherDecryption(String[] cipherText, SymmetricKey key, Method streamMethod) {

        switch (streamMethod) {
            case CBC:
                return CBCStreamCipherDecryption(cipherText, key);
            case CTR:
                return CTRStreamCipherDecryption(cipherText, key);
            default:
                return CTRStreamCipherDecryption(cipherText, key);
        }
    }

    private static String[] CBCStreamCipherDecryption(String[] cipherText, SymmetricKey key) {

        String[][] block = new String[4][4];

        String[] plainText = new String[cipherText.length];
        String[] IVconcatCipher = Helper.concatenateArrays(Helper.unrollStringArray(IV),cipherText);
        int totalCycle = plainText.length / 16;
        int index = 0;
        for (int i = 0; i < totalCycle; i++) {
            for (int j = 0; j <4 ; j++) {
                for (int k = 0; k <4 ; k++) {
                    block[k][j] = cipherText[(j<<2) +k +index];
                }
            }
            blockCipherDecryption(block, key);

            for (int j = 0; j < 4; j++) {
                for (int k = 0; k < 4; k++) {
                    String result = Helper.hexXOR(block[k][j], IVconcatCipher[index]);
                    plainText[index] = result;
                    index++;
                }
            }
        }
        int unencryptedPartLength = cipherText.length - index;
        while (unencryptedPartLength > 0) {
            plainText[index] = cipherText[index];
            unencryptedPartLength--;
            index++;
        }
        return plainText;
    }

    private static String[] CTRStreamCipherDecryption(String[] cipherText, SymmetricKey key) {

        BigInteger maxValueFor8Byte = new BigInteger("FFFFFFFFFFFFFFFF", 16);
        BigInteger counter = BigInteger.ZERO;
        String[] plainText = new String[cipherText.length];
        ArrayList<BigInteger> counterList = new ArrayList<>();

        int totalCycle = cipherText.length / 16;

        for (int i = 0; i <totalCycle ; i++) {
            counterList.add(counter);
            counter=counter.add(BigInteger.ONE).mod(maxValueFor8Byte);
        }

        counterList.parallelStream().forEach(cnt -> {
            String[][] block = generateBlockForCTR(cnt);
            blockCipherEncryption(block, key);
            int i = cnt.intValue();
            for (int j = 0; j < 4; j++) {
                for (int k = 0; k < 4; k++) {
                    int index = (i<<4) + (j<<2) + k;
                    String result = Helper.hexXOR(block[k][j], cipherText[index]);
                    plainText[index] = result;
                }
            }
        });

        for (int i = plainText.length - 16; i < plainText.length; i++) {

            if(plainText[i] == null) plainText[i] = cipherText[i];
        }
        return plainText;
    }

    private static void blockCipherEncryption(String[][] block, SymmetricKey key) {

        String[][][] expandedKey = keyExpand(key);
        int totalKey = expandedKey.length;

        addRoundKey(block, expandedKey[0]); //Add round cryptography.key with cryptography.key 0

        for (int i = 1; i < totalKey - 1; i++) { //Main Rounds
            subBytes(block);
            shiftRows(block);
            mixColumns(block);
            addRoundKey(block, expandedKey[i]);
        }

        subBytes(block);
        shiftRows(block);
        addRoundKey(block, expandedKey[totalKey - 1]);
    }

    private static void blockCipherDecryption(String[][] block, SymmetricKey key) {

        String[][][] expandedKey = keyExpand(key);
        int totalKey = expandedKey.length;

        addRoundKey(block, expandedKey[totalKey -1]); //Add round cryptography.key with last cryptography.key

        for (int i = totalKey -2; i >0; i--) { //Main Rounds
            inverseShiftRows(block);
            inverseSubBytes(block);
            addRoundKey(block, expandedKey[i]);
            inverseMixColumns(block);
        }

        inverseShiftRows(block);
        inverseSubBytes(block);
        addRoundKey(block, expandedKey[0]);
    }

    private static void generateInitializationVector() {

        for (int i = 0; i < 4; i++) {
            for (int j = 0; j < 4; j++) {

                IV[i][j] = String.format("%02x", new SecureRandom().nextInt(256)).toUpperCase();
            }
        }
    }

    private static void generateNonce(int length) {
        nonce = new String[length/2];
        for (int i = 0; i < length/2; i++) {
            nonce[i] = String.format("%02x", new SecureRandom().nextInt(256)).toUpperCase();
        }
    }

    private static String[][] generateBlockForCTR(BigInteger counter) {

        String counterAsHex = counter.toString(16);
        String formattedHex = ("0000000000000000" + counterAsHex).substring(counterAsHex.length()).toUpperCase();

        formattedHex = formattedHex.replaceAll("(.{" + 2 + "})", "$1 ").trim();
        String[] counterHexArray = formattedHex.split(" ");

        String[][] block = new String[4][4];
        BigInteger blockNumber = counter.multiply(BigInteger.valueOf(8));

        for (int i = 0; i < 2; i++) {
            for (int j = 0; j < 4; j++) {
                block[j][i] = nonce[blockNumber.intValue() + (i<<2) + j];
            }
        }
        for (int i = 0; i < 2; i++) {
            for (int j = 0; j < 4; j++) {
                block[j][i+2] = counterHexArray[(i<<2) + j];
            }
        }
        return block;
    }

    private static String[][][] keyExpand(SymmetricKey key) {

        String keyAsHex = key.getSymetricKeyAsHex();

        ArrayList<String> expandedKeyAsLine = new ArrayList<>();
        keyAsHex = keyAsHex.replaceAll("(.{" + 2 + "})", "$1 ").trim();

        expandedKeyAsLine.addAll(Arrays.asList(keyAsHex.split(" ")));

        expandKeyLoop(expandedKeyAsLine);
        return generateKeys(expandedKeyAsLine);

    }

    private static String[][][] generateKeys(ArrayList<String> expandedKeyAsLine) {

        int totalKeyNumber = 11;

        switch (expandedKeyAsLine.size()) {
            case 176:
                totalKeyNumber = 11;
                break;
            case 208:
                totalKeyNumber = 13;
                break;
            case 240:
                totalKeyNumber = 15;
                break;

        }

        String[][][] expandedKey = new String[totalKeyNumber][4][4];

        for (int i = 0; i < totalKeyNumber; i++) {
            for (int j = 0; j < 4; j++) {
                for (int k = 0; k < 4; k++) {

                    expandedKey[i][k][j] = expandedKeyAsLine.get((i << 4) + (j << 2) + k);

                }
            }
        }
        return expandedKey;
    }

    private static void expandKeyLoop(ArrayList<String> expandedKey) {

        int keyByte = expandedKey.size();
        int c = keyByte;
        int i = 0;
        int indexCtr = 0;

        int totalByte;

        switch (keyByte) {
            case 16:
                totalByte = 176;
                break;
            case 24:
                totalByte = 208;
                break;
            case 32:
                totalByte = 240;
                break;
            default:
                totalByte = 176;
        }


        while (c < totalByte) {

            if (c % keyByte == 0) {
                List<String> rootWord = new ArrayList<>(expandedKey.subList(c - 4, c));
                Collections.rotate(rootWord, -1);
                rootWord.forEach(s -> rootWord.set(rootWord.indexOf(s), subByte(s)));
                String[] rcon = RCON[i];
                List<String> firstWord = new ArrayList<>(expandedKey.subList(indexCtr, indexCtr + 4));


                for (int j = 0; j < 4; j++) {

                    String newHex = Helper.hexXOR(rootWord.get(j), rcon[j]);
                    newHex = Helper.hexXOR(newHex, firstWord.get(j));
                    rootWord.set(j, newHex);
                }
                expandedKey.addAll(rootWord);
                c += 4;
                i++;
                indexCtr += 4;
                continue;
            }

            List<String> firstWord = new ArrayList<>(expandedKey.subList(indexCtr, indexCtr + 4));
            List<String> secondWord = new ArrayList<>(expandedKey.subList(indexCtr + keyByte - 4, indexCtr + keyByte));

            for (int j = 0; j < 4; j++) {

                String newHex = Helper.hexXOR(firstWord.get(j), secondWord.get(j));
                expandedKey.add(newHex);
            }
            c += 4;
            indexCtr += 4;
        }
    }

    private static String subByte(String hex) {

        int decimalValue = Integer.parseInt(hex, 16);
        int changedValue = SBOX[decimalValue];

        String str = Integer.toHexString(changedValue).toUpperCase();
        return ("00" + str).substring(str.length()).toUpperCase();
    }

    private static String subByteInverse(String hex) {

        int decimalValue = Integer.parseInt(hex, 16);

        for (int i = 0; i < SBOX.length; i++) {
            if(decimalValue == SBOX[i]) {
                int i1 = i / 16;
                int i2 = i % 16;

                StringBuilder sb = new StringBuilder();
                sb.append(Integer.toHexString(i1));
                sb.append(Integer.toHexString(i2));

                return sb.toString().toUpperCase();
            }
        }
        return null;
    }

    private static void addRoundKey(String[][] block, String[][] key) {

        for (int i = 0; i < 4; i++) {
            for (int j = 0; j < 4; j++) {

                block[i][j] = Helper.hexXOR(block[i][j], key[i][j]);
            }
        }
    }

    private static void subBytes(String[][] block) {

        for (int i = 0; i < 4; i++) {
            for (int j = 0; j < 4; j++) {

                block[i][j] = subByte(block[i][j]);
            }
        }
    }

    private static void inverseSubBytes(String[][] block) {

        for (int i = 0; i < 4; i++) {
            for (int j = 0; j < 4; j++) {

                block[i][j] = subByteInverse(block[i][j]);
            }
        }
    }

    private static void shiftRows(String[][] block) {

        for (int i = 0; i < 4; i++) {
            List<String> currentRow = Arrays.asList(block[i]);
            Collections.rotate(currentRow, -i);
        }
    }

    private static void inverseShiftRows(String[][] block) {

        for (int i = 0; i < 4; i++) {
            List<String> currentRow = Arrays.asList(block[i]);
            Collections.rotate(currentRow, i);
        }
    }

    private static void mixColumns(String[][] block) {

        for (int i = 0; i < 4; i++) {
            String[] column = new String[4];
            for (int j = 0; j < 4; j++) {
                column[j] = block[j][i];
            }
            mixColumn(column);
            for (int j = 0; j < 4; j++) {
                block[j][i] = column[j];
            }
        }
    }

    private static void inverseMixColumns(String[][] block) {

        for (int i = 0; i < 4; i++) {
            String[] column = new String[4];
            for (int j = 0; j < 4; j++) {
                column[j] = block[j][i];
            }
            inverseMixColumn(column);
            for (int j = 0; j < 4; j++) {
                block[j][i] = column[j];
            }
        }
    }

    private static void mixColumn(String[] column) {

        String[] temp = new String[column.length];
        for (int i = 0; i < 4; i++) {
            String tempResult = "00";
            for (int j = 0; j < 4; j++) {
                String mulpResult = polynomialMulp(column[j], GALOIS_FIELD[i][j]);
                tempResult = polynomialAdd(mulpResult, tempResult);
            }
            temp[i] = polynomialMod(tempResult);
        }
        for (int i = 0; i < column.length; i++) {
            column[i] = temp[i];
        }
    }

    private static void inverseMixColumn(String[] column) {

        String[] temp = new String[column.length];
        for (int i = 0; i < 4; i++) {
            String tempResult = "00";
            for (int j = 0; j < 4; j++) {
                String mulpResult = polynomialMulp(column[j], GALOIS_FIELD_INVERSE[i][j]);
                tempResult = polynomialAdd(mulpResult, tempResult);
            }
            temp[i] = polynomialMod(tempResult);
        }
        for (int i = 0; i < column.length; i++) {
            column[i] = temp[i];
        }
    }

    private static String polynomialAdd(String polyn1, String polyn2) {

        int poly1AsDecimal = Integer.valueOf(polyn1, 16);
        int poly2AsDecimal = Integer.valueOf(polyn2, 16);

        int result = poly1AsDecimal ^ poly2AsDecimal;
        return Integer.toHexString(result);
    }

    private static String polynomialMulp(String multiplicand, int multiplier) {

        String multiplierAsBinary = Integer.toString(multiplier, 2);
        int multiplierAsDecimal = Integer.valueOf(multiplicand, 16);
        int result = 0;

        int degree = 0;
        for (int i = multiplierAsBinary.length() - 1; i >= 0; i--) {
            if (multiplierAsBinary.charAt(i) == '1') {
                result = result ^ (multiplierAsDecimal << degree);
            }
            degree++;
        }
        return Integer.toString(result, 16);
    }

    private static String polynomialMod(String hexValue) {

        Integer decimalValue = Integer.valueOf(hexValue, 16);
        String binaryValue = Integer.toString(decimalValue, 2);

        int differ = binaryValue.length() - GALOIS_MODULO_VALUE.length();

        if (differ < 0) return ("00" + hexValue).substring(hexValue.length()).toUpperCase();

        Integer galoisAsDecimal = Integer.valueOf(GALOIS_MODULO_VALUE, 2);
        int galoisAsDecimalExtended = galoisAsDecimal << differ;

        int result = decimalValue;

        while (true) {
            differ = Integer.toString(result,2).length() - GALOIS_MODULO_VALUE.length();
            galoisAsDecimalExtended = galoisAsDecimal << differ;
            result = result ^ galoisAsDecimalExtended;

            if (Integer.toString(result, 2).length() < GALOIS_MODULO_VALUE.length()) {
                String str = Integer.toHexString(result);
                return ("00" + str).substring(str.length()).toUpperCase();
            }
        }
    }
}

