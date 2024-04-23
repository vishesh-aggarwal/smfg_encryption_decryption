package com.practice;

import javax.crypto.*;
import javax.crypto.spec.SecretKeySpec;

import org.apache.commons.codec.binary.Base64;
import org.bouncycastle.crypto.engines.AESEngine;
import org.bouncycastle.crypto.paddings.PKCS7Padding;
import org.bouncycastle.crypto.params.KeyParameter;

import org.bouncycastle.crypto.BlockCipher;
import org.bouncycastle.crypto.DataLengthException;
import org.bouncycastle.crypto.InvalidCipherTextException;
import org.bouncycastle.crypto.engines.AESEngine;
import org.bouncycastle.crypto.paddings.BlockCipherPadding;
import org.bouncycastle.crypto.paddings.PaddedBufferedBlockCipher;
import org.bouncycastle.crypto.params.KeyParameter;
import org.bouncycastle.jce.provider.BouncyCastleProvider;

import java.security.*;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.PKCS8EncodedKeySpec;
import java.security.spec.X509EncodedKeySpec;

import org.bouncycastle.crypto.BlockCipher;
import org.bouncycastle.crypto.DataLengthException;
import org.bouncycastle.crypto.InvalidCipherTextException;
import org.bouncycastle.crypto.engines.AESEngine;
import org.bouncycastle.crypto.paddings.BlockCipherPadding;
import org.bouncycastle.crypto.paddings.PaddedBufferedBlockCipher;
import org.bouncycastle.crypto.params.KeyParameter;

// then press Enter. You can now see whitespace characters in your code.
public class Main {
        public static void main(String[] args) {
                String publicKey = "MIGfMA0GCSqGSIb3DQEBAQUAA4GNADCBiQKBgQCgFGVfrY4jQSoZQWWygZ83roKXWD4YeT2x2p41dGkPixe73rT2IW04glagN2vgoZoHuOPqa5and6kAmK2ujmCHu6D1auJhE2tXP+yLkpSiYMQucDKmCsWMnW9XlC5K7OSL77TXXcfvTvyZcjObEz6LIBRzs6+FqpFbUO9SJEfh6wIDAQAB";
                String aesKey = "8wxoTnDywJC5WpruGPqlbjjCugl776VqP6NAMpq2z2E=";
                String payload = "{\"partnerapplicationid\":\"ANGEL08379721603\",\"partnerid\":\"ANGEL1\",\"leaddetails\":{\"firstname\":\"RMAAAAA\",\"middlename\":\"\",\"lastname\":\"STAAAAAA\",\"mobilenumber\":\"8779885603\",\"emailaddress\":\"manoj@gmail.com\",\"producttype\":\"BL\",\"currentpincode\":\"500032\"},\"basicdetails\":{\"nationality\":\"234256\",\"dob\":\"21-04-1984\",\"pannumber\":\"AQNPG3603P\",\"monthlyincome\":\"47777\",\"famhouseholdinc\":\"1233\",\"consentmode\":\"OTP\",\"consentdate\":\"16-01-2024\",\"pep\":\"234248\",\"employmenttype\":\"20556\",\"avgmontlycr\":\"47777\",\"gstannualturnover\":\"47777\",\"gender\":\"20628\"},\"additionalinfo\":{},\"loandetails\":{\"loanamount\":\"50000\",\"tenure\":\"24\",\"offertype\":\"236695\"}}";
                // try {
                // String AESKey = encrypt(payload, publicKey);
                // } catch (Exception e) {
                //
                // }

                // to encrypt/decrypt the DATA REQUEST
                String txt = "Root@2024";
                String encrystr = AESEncryptionDecryption.getAESEncryptString(payload, aesKey);
                System.out.print("encrystr ");
                System.out.println(encrystr);
                String decStr = AESEncryptionDecryption.getAESDecryptString(
                                encrystr,
                                aesKey);

                System.out.println(decStr);

                // to encrypt/decrypt the Key that needs to be passed in the API as well
                try {
                        String mainKey = encrypt(aesKey, publicKey);
                        System.out.print("mainKey ");
                        System.out.println(mainKey);
                } catch (Exception e) {
                        e.printStackTrace();
                }

        }

        public static String aesDecrypt(String encryptedStr, String secretKeyStr) {

                try {
                        Security.addProvider(new BouncyCastleProvider());

                        byte[] decodedKey = Base64.decodeBase64(secretKeyStr);

                        SecretKey originalKey = new SecretKeySpec(decodedKey, "AES");

                        AESBouncyCastle abc = new AESBouncyCastle();

                        abc.setPadding(new PKCS7Padding());

                        abc.setKey(originalKey.getEncoded());

                        String originalText = new String(abc.decrypt(Base64.decodeBase64(encryptedStr.getBytes())),
                                        "UTF8");
                        System.out.println("originalText " + originalText);
                        // System.out.println("originalText after trim "+originalText.trim());
                        return originalText.trim();

                } catch (Exception e) {
                        e.printStackTrace();
                }

                return null;

        }

        public static String aesEncrypt(String originalText, String secretKeyStr) {

                try {

                        Security.addProvider(new org.bouncycastle.jce.provider.BouncyCastleProvider());

                        byte[] decodedKey = Base64.decodeBase64(secretKeyStr);

                        SecretKey originalKey = new SecretKeySpec(decodedKey, "AES");

                        AESBouncyCastle abc = new AESBouncyCastle();

                        abc.setPadding(new PKCS7Padding());

                        abc.setKey(originalKey.getEncoded());

                        String encryptedParam = new String(Base64.encodeBase64(abc.encrypt(originalText.getBytes())));

                        return encryptedParam;

                } catch (Exception e) {
                        e.printStackTrace();
                }

                return null;
        }

        public static PublicKey getPublicKey(String base64PublicKey) {
                PublicKey publicKey = null;
                try {
                        X509EncodedKeySpec keySpec = new X509EncodedKeySpec(
                                        java.util.Base64.getDecoder().decode(base64PublicKey.getBytes()));
                        KeyFactory keyFactory = KeyFactory.getInstance("RSA");
                        publicKey = keyFactory.generatePublic(keySpec);
                        return publicKey;
                } catch (NoSuchAlgorithmException e) {
                        e.printStackTrace();
                } catch (InvalidKeySpecException e) {
                        e.printStackTrace();
                }
                return publicKey;
        }

        public static PrivateKey getPrivateKey(String base64PrivateKey) {
                PrivateKey privateKey = null;
                PKCS8EncodedKeySpec keySpec = new PKCS8EncodedKeySpec(
                                java.util.Base64.getDecoder().decode(base64PrivateKey.getBytes()));
                KeyFactory keyFactory = null;
                try {
                        keyFactory = KeyFactory.getInstance("RSA");
                } catch (NoSuchAlgorithmException e) {
                        e.printStackTrace();
                }
                try {
                        privateKey = keyFactory.generatePrivate(keySpec);
                } catch (InvalidKeySpecException e) {
                        e.printStackTrace();
                }
                return privateKey;
        }

        public static String encrypt(String data, String publicKey)
                        throws BadPaddingException, IllegalBlockSizeException, InvalidKeyException,
                        NoSuchPaddingException, NoSuchAlgorithmException, InvalidKeyException {
                Cipher cipher = Cipher.getInstance("RSA/ECB/PKCS1Padding");
                cipher.init(Cipher.ENCRYPT_MODE, getPublicKey(publicKey));
                return java.util.Base64.getEncoder().encodeToString(cipher.doFinal(data.getBytes()));
        }

        public static String decrypt(byte[] data, PrivateKey privateKey) throws NoSuchPaddingException,
                        NoSuchAlgorithmException, InvalidKeyException, BadPaddingException, IllegalBlockSizeException {
                Cipher cipher = Cipher.getInstance("RSA/ECB/PKCS1Padding");
                cipher.init(Cipher.DECRYPT_MODE, privateKey);
                return new String(cipher.doFinal(data));
        }
}

// package com.practice;

// import java.io.UnsupportedEncodingException;
// import java.security.Security;

// import javax.crypto.SecretKey;
// import javax.crypto.spec.SecretKeySpec;

// import org.apache.commons.codec.binary.Base64;
// import org.bouncycastle.crypto.paddings.PKCS7Padding;

// import org.bouncycastle.crypto.BlockCipher;
// import org.bouncycastle.crypto.DataLengthException;
// import org.bouncycastle.crypto.InvalidCipherTextException;
// import org.bouncycastle.crypto.engines.AESEngine;
// import org.bouncycastle.crypto.paddings.BlockCipherPadding;
// import org.bouncycastle.crypto.paddings.PaddedBufferedBlockCipher;
// import org.bouncycastle.crypto.params.KeyParameter;

// public class Main {

// public static void main(String[] args) {
// BlockCipher AESCipher = new AESEngine();
// PaddedBufferedBlockCipher pbbc;
// KeyParameter key;

// String payload =
// "{\"partnerapplicationid\":\"ANGEL08379721603\",\"partnerid\":\"ANGEL1\",\"leaddetails\":{\"firstname\":\"RMAAAAA\",\"middlename\":\"\",\"lastname\":\"STAAAAAA\",\"mobilenumber\":\"8779885603\",\"emailaddress\":\"manoj@gmail.com\",\"producttype\":\"BL\",\"currentpincode\":\"500032\"},\"basicdetails\":{\"nationality\":\"234256\",\"dob\":\"21-04-1984\",\"pannumber\":\"AQNPG3603P\",\"monthlyincome\":\"47777\",\"famhouseholdinc\":\"1233\",\"consentmode\":\"OTP\",\"consentdate\":\"16-01-2024\",\"pep\":\"234248\",\"employmenttype\":\"20556\",\"avgmontlycr\":\"47777\",\"gstannualturnover\":\"47777\",\"gender\":\"20628\"},\"additionalinfo\":{},\"loandetails\":{\"loanamount\":\"50000\",\"tenure\":\"24\",\"offertype\":\"236695\"}}";
// String secretKeyStr = "8wxoTnDywJC5WpruGPqlbjjCugl776VqP6NAMpq2z2E=";
// String encryptedStr =
// "4c8871c5c25004baeb863aa2f662e0f1d3ef14b43967fbc17ef92b384b554ac5d18b13ae973856685a594705adc476133d9b376c10dbc0c4d680991c2202cacb86e297b3d019b62fe4692552a0e13b90c74657dffc63664c89e6cd6d1eb52360279e6971ab780d671d5fc88e6ccf86f6e97f6afedbeeaacf44d9c5379b52a95071a911f673156695c64db73b443f68ba18dac819cce192da696571f5fef09edf477ef49cce69cd103bed0edb60fafef767144b2e86bedf633c3f85fe033f17c961a1a6b5d09c698f80fd0a036254f1dbe773bbcd0010db7d4cd0bc6bb8efce0721284785727d122a0b7185622d0db0eaf5744518aad766f93fdc4c58be1f4535ddde9755d3887cdc609a718e1f984188e54cf586ce744efdbae729d44b628ecc468cfb7bbd07674405d0ab81648441d802102012b4da44b1c8a7469bd8f3d5a0c40f859b41e7baa29afe0dffb5072b56202f81bce1a047b4225c93d87a1d96f12db580d35c91781736f5f4b4dc04c5f59f799e32b5fa35f5be6b092b3325da9149ecdf220c240123f1f42de18743754ffc34dbe2d077772a4350bda148472e4e5da0fa7fffaf751ded4f8f63fdc9bfb46400c7151ef3f91410867a2c96283efae71d96d930a9ba8c9d109eaf6c5b6ba8dbd68f532207adf91480c82ba6cdd6b92201a9575a3e21ce7584f3fba686bf313e6e8b0acc95d10597400b792a81ed09462f653391bba098a8e90cc8e3ec63165155a2207630a430477677b7587e69e34318d89596c8677846c2f371d0015447fafd9414c40d277a0248410037f00a762e53546076dd85057b27007fa6e5827e327c913f80bd9edcda2fc1fcfdf423b2ae5e8d2cdd400d8d2f3caf9127871faa23c4943b8809af18046a805f71b1e9f2f7";

// // String encryptedParam = new
// String(Base64.encodeBase64(abc.encrypt(originalText.getBytes())));

// // return encryptedParam;

// Security.addProvider(new
// org.bouncycastle.jce.provider.BouncyCastleProvider());

// byte[] decodedKey = Base64.decodeBase64(secretKeyStr);

// SecretKey originalKey = new SecretKeySpec(decodedKey, "AES");

// pbbc = new PaddedBufferedBlockCipher(AESCipher, new PKCS7Padding());
// key = new KeyParameter(originalKey.getEncoded());

// byte[] input = Base64.decodeBase64(encryptedStr);

// pbbc.init(false, key);

// byte[] output = new byte[pbbc.getOutputSize(input.length)];
// int bytesWrittenOut = pbbc.processBytes(
// input, 0, input.length, output, 0);
// System.out.println(bytesWrittenOut);
// try {
// pbbc.doFinal(output, bytesWrittenOut);
// } catch (DataLengthException e) {
// // TODO Auto-generated catch block
// e.printStackTrace();
// } catch (IllegalStateException e) {
// // TODO Auto-generated catch block
// e.printStackTrace();
// } catch (InvalidCipherTextException e) {
// // TODO Auto-generated catch block
// e.printStackTrace();
// }

// String originalText;
// try {
// originalText = new String(output, "UTF8");
// System.out.println(originalText.trim());
// } catch (UnsupportedEncodingException e) {
// // TODO Auto-generated catch block
// e.printStackTrace();
// }

// }

// }