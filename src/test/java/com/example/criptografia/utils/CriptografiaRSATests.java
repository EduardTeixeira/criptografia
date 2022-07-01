package com.example.criptografia.utils;

import static org.junit.jupiter.api.Assertions.assertEquals;

import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;

import javax.crypto.BadPaddingException;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;

import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;

@SpringBootTest
public class CriptografiaRSATests {

	@Autowired
	private CriptografiaRSA criptografiaRSA;

	@Test
	public void decrypt() throws InvalidKeyException, NoSuchPaddingException, NoSuchAlgorithmException,
			BadPaddingException, IllegalBlockSizeException {

		String valueToDecrypt = "nFMSRfBYmU4JBTQARX258w1xvejPFHbxylscalbRI/+Mu5QASJFnKMQx7vD2EkYUd3y72MHZtD8fSOV/vp2jPma4PwSxamsvc+GFTCGmoThJA8b1aNYvWAl6cqgTiHrN0nvdtfFcNYm0Pihfcdxr9IajvvvbTACdlmpqh8Zhi4U=";

		String expectResult = "Édu@ard";

		String decryptValue = criptografiaRSA.decrypt(valueToDecrypt);

		assertEquals(expectResult, decryptValue);

	}

	@Test
	public void encrypt() throws InvalidKeyException, NoSuchPaddingException, NoSuchAlgorithmException,
			BadPaddingException, IllegalBlockSizeException {

		String value = "Édu@ard";

		String encryptValue = criptografiaRSA.encrypt(value);

		String decryptValue = criptografiaRSA.decrypt(encryptValue);

		assertEquals(value, decryptValue);

	}

}
