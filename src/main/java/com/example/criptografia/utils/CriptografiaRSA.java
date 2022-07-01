package com.example.criptografia.utils;

import java.security.InvalidKeyException;
import java.security.KeyFactory;
import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.PKCS8EncodedKeySpec;
import java.security.spec.X509EncodedKeySpec;
import java.util.Base64;

import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;

import org.springframework.stereotype.Component;

@Component
public class CriptografiaRSA {

	private static String PRIVATE_KEY = "MIICdQIBADANBgkqhkiG9w0BAQEFAASCAl8wggJbAgEAAoGBAOkQX84LuZCKoWrZW19Ohk4ZwFlAXoBVPDsA7JDz4RpDmsmzMnzkTSF2irt0/2rg5Yk8Si26XilFezwogF3WwxFgLuRuqGygu1aFgP1W43vDUJFpE9RMqGCEMc42oF6fWCBW47DQbrU7JCAppeqZVz6aZIsc0zcio+r9dil2QJW/AgMBAAECgYAQ20JSoL53Gc+67qWRKxjDpVEoI2OyXHfSvKpfgYQSZjlXxUItjkWV2gEGtduTW1i+qEGlNQmCaqgTHcrK/rF0+Ow0iy9g7SFyRFqM0O4z5DSnke7zARWTpRQ4cfp+DxGG5TOfqOJSSzLKxRfJIcWkEHlb4SViNkrNnCbCY7Q1oQJBAPnl3uN11W0p+kcw2nFhPn3yJ61xTCSUyfyALqk+ERjvEpn9bAbFgrNDTMd8pF3DO8MHW7VSrIH3L07s0tpww+MCQQDuwUX0aQZuarkKa7m3VJyguLosfAb3cALV58PxdwpBFf2aoU6yp4N2GtUeMEiGZGJuFCWMKN3RcYuQDkcjH+V1AkAt85IHu3wyZZyrCJWycZI/MI8ROpsowt9deeiaoFoefp+qB0qc+CavdfmhWQ8UWrkbhLfdYMVt5JkjZzLijgfHAkAwM4ba/CUXP6aR6wO4dnWUoRa9CmEhrVR1OPA/HIhOcZEcmbpYqScKPgqOqLLLpxKUJK8b59g4g5Loh2lnNvZNAkAr8MFFNTV7lAC36mTYecdO0J/A8XkIPQkYa7z6x+qDpUyfTHf+ELkMKdqSi/0Tsn+xdBWeGGgLMSQbbY8TYErJ";
	private static String PUBLIC_KEY = "MIGfMA0GCSqGSIb3DQEBAQUAA4GNADCBiQKBgQDpEF/OC7mQiqFq2VtfToZOGcBZQF6AVTw7AOyQ8+EaQ5rJszJ85E0hdoq7dP9q4OWJPEotul4pRXs8KIBd1sMRYC7kbqhsoLtWhYD9VuN7w1CRaRPUTKhghDHONqBen1ggVuOw0G61OyQgKaXqmVc+mmSLHNM3IqPq/XYpdkCVvwIDAQAB";
	private static String CIPHER_TRANSFORMATION = "RSA/ECB/PKCS1Padding";

//	public static void main(String[] args)
//			throws IllegalBlockSizeException, InvalidKeyException, NoSuchPaddingException, BadPaddingException {
//
//		try {
//
//			String encryptedString = Base64.getEncoder().encodeToString(encrypt("Eduard"));
//
//			System.out.println(encryptedString);
//
//			String decryptedString = decrypt(encryptedString);
//
//			System.out.println(decryptedString);
//
//		} catch (NoSuchAlgorithmException e) {
//
//			System.err.println(e.getMessage());
//
//		}
//
//	}

	private PublicKey getPublicKey(String base64PublicKey) {

		PublicKey publicKey = null;

		try {

			X509EncodedKeySpec keySpec = new X509EncodedKeySpec(Base64.getDecoder().decode(base64PublicKey.getBytes()));

			KeyFactory keyFactory = KeyFactory.getInstance("RSA");

			publicKey = keyFactory.generatePublic(keySpec);

			return publicKey;

		} catch (NoSuchAlgorithmException | InvalidKeySpecException exception) {

			exception.printStackTrace();

		}

		return null;

	}

	private PrivateKey getPrivateKey(String base64PrivateKey) {

		PrivateKey privateKey = null;

		PKCS8EncodedKeySpec keySpec = new PKCS8EncodedKeySpec(Base64.getDecoder().decode(base64PrivateKey.getBytes()));

		KeyFactory keyFactory = null;

		try {

			keyFactory = KeyFactory.getInstance("RSA");

			privateKey = keyFactory.generatePrivate(keySpec);

			return privateKey;

		} catch (NoSuchAlgorithmException | InvalidKeySpecException exception) {

			exception.printStackTrace();

		}

		return null;

	}

	public String encrypt(String data) throws BadPaddingException, IllegalBlockSizeException, InvalidKeyException,
			NoSuchPaddingException, NoSuchAlgorithmException {

		Cipher cipher = Cipher.getInstance(CIPHER_TRANSFORMATION);

		cipher.init(Cipher.ENCRYPT_MODE, getPublicKey(PUBLIC_KEY));

		return Base64.getEncoder().encodeToString(cipher.doFinal(data.getBytes()));

	}

	public String decrypt(String data) throws NoSuchPaddingException, NoSuchAlgorithmException, InvalidKeyException,
			BadPaddingException, IllegalBlockSizeException {

		Cipher cipher = Cipher.getInstance(CIPHER_TRANSFORMATION);

		cipher.init(Cipher.DECRYPT_MODE, getPrivateKey(PRIVATE_KEY));

		return new String(cipher.doFinal(Base64.getDecoder().decode(data.getBytes())));

	}

}
