package com.goodbyeq.authorize.encryption;

import java.security.NoSuchAlgorithmException;
import java.security.spec.InvalidKeySpecException;

import javax.crypto.SecretKey;
import javax.crypto.SecretKeyFactory;
import javax.crypto.spec.PBEKeySpec;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.stereotype.Component;

/**
 * 
 * @author vakey
 *
 */
@Component
public abstract class KeyGenerator {
	
	private static final Logger LOGGER = LoggerFactory.getLogger(KeyGenerator.class);

	public SecretKey generateKey(String keyGenAlgorithm, char[] password, byte[] salt, int iterationCount,
			int keyLength) {

		PBEKeySpec pbeKeySpec = new PBEKeySpec(password, salt, iterationCount, keyLength);

		SecretKeyFactory secretKeyFactory;
		SecretKey secretKey = null;
		try {
			secretKeyFactory = SecretKeyFactory.getInstance(keyGenAlgorithm);

			secretKey = secretKeyFactory.generateSecret(pbeKeySpec);

		} catch (NoSuchAlgorithmException e) {
			LOGGER.info("There is no such Algorithm");
		} catch (InvalidKeySpecException e) {
			LOGGER.info("Invalid key Specification");
		} finally {
			pbeKeySpec.clearPassword();
		}

		return secretKey;
	}

	public abstract SecretKey generateKey(char[] password);

}
