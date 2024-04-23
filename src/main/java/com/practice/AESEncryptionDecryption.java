package com.practice;

import java.security.Security;

import javax.crypto.SecretKey;
import javax.crypto.spec.SecretKeySpec;



import org.apache.commons.codec.binary.Base64;
import org.bouncycastle.crypto.paddings.PKCS7Padding;

public class AESEncryptionDecryption {

    public static String getAESDecryptString(String encryptedStr, String secretKeyStr) {

        try {

            Security.addProvider(new org.bouncycastle.jce.provider.BouncyCastleProvider());

            byte[] decodedKey = Base64.decodeBase64(secretKeyStr);

            SecretKey originalKey = new SecretKeySpec(decodedKey, "AES");

            AESBouncyCastle abc = new AESBouncyCastle();

            abc.setPadding(new PKCS7Padding());

            abc.setKey(originalKey.getEncoded());

            String originalText = new String(abc.decrypt(Base64.decodeBase64(encryptedStr)), "UTF8");

            return originalText.trim();

        } catch (Exception e) {

            e.printStackTrace();

        }

        return null;

    }







    public static String getAESEncryptString(String originalText, String secretKeyStr) {

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

}