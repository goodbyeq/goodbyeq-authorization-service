package com.goodbyeq.authorize.encryption;

import javax.crypto.SecretKey;

import org.springframework.stereotype.Component;

/**
 * 
 * @author vakey
 *
 */
@Component("encryptionKeyGenerator")
public class EncryptionKeyGenerator extends KeyGenerator{
	
	public static final String ENCRYPTION_KEY_ID = "BL-SC-Enc-Cookie-Key";
	
	private static final String KEYGEN_ALGORITHM = "AES";
	
	private static final byte[] SALT = { 
		(byte) 0xAA, (byte) 0x0,  (byte) 0x76, (byte) 0xDE, 
		(byte) 0xB8, (byte) 0x7A, (byte) 0x12, (byte) 0x1D,
		(byte) 0x41, (byte) 0xe9, (byte) 0x6E, (byte) 0x2E, 
		(byte) 0xAE, (byte) 0xBF, (byte) 0xC4, (byte) 0xFB 
	};

	private static final int ITERATION_COUNT = 1000;

	private static final int ENCRYPTION_KEY_LENGTH = 256;
	
	@Override
	public SecretKey generateKey(char[] password) {		
		return generateKey(KEYGEN_ALGORITHM, password, SALT, ITERATION_COUNT,
				ENCRYPTION_KEY_LENGTH);
	}

}
