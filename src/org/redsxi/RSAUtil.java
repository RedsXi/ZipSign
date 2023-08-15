package org.redsxi;

import java.security.*;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.PKCS8EncodedKeySpec;
import java.security.spec.X509EncodedKeySpec;

public class RSAUtil {

    private static final String ALGORITHM = "RSA";

    public static byte[][] generateRSAKeypair() {
        try {
            KeyPairGenerator generator = KeyPairGenerator.getInstance("RSA");
            generator.initialize(1024);
            KeyPair pair = generator.genKeyPair();
            PublicKey publicKey = pair.getPublic();
            PrivateKey privateKey = pair.getPrivate();
            return new byte[][]{publicKey.getEncoded(), privateKey.getEncoded()};
        } catch (Exception e) {
            throw new RuntimeException(e);
        }
    }

    private static KeyFactory getFactory() {
        try {
            return KeyFactory.getInstance(ALGORITHM);
        } catch (NoSuchAlgorithmException e) {
            throw new RuntimeException("This runtime doesn't support RSA.", e);
        }
    }

    public static PublicKey getRSAPublicKey(byte[] encoded) {
        X509EncodedKeySpec spec = new X509EncodedKeySpec(encoded, ALGORITHM);
        try {
            return getFactory().generatePublic(spec);
        } catch (InvalidKeySpecException e) {
            throw new RuntimeException("Key spec error", e);
        }
    }

    public static PrivateKey getRSAPrivateKey(byte[] encoded) {
        PKCS8EncodedKeySpec spec = new PKCS8EncodedKeySpec(encoded, ALGORITHM);
        try {
            return getFactory().generatePrivate(spec);
        } catch (InvalidKeySpecException e) {
            throw new RuntimeException("Key spec error", e);
        }
    }
}
