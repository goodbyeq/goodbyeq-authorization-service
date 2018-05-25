package com.goodbyeq.authorize.encryption;

import javax.crypto.SecretKey;

import org.springframework.stereotype.Component;

/**
 * 
 * @author vakey
 *
 */
@Component("hmacKeyGenerator")
public class HmacKeyGenerator extends KeyGenerator{
	
	private static final byte[] SALT = { 
		(byte) 0x1C, (byte) 0x33, (byte) 0x18, (byte) 0x63, 
		(byte) 0xC8, (byte) 0xA4, (byte) 0x3F, (byte) 0xD2,
		(byte) 0x30, (byte) 0x08, (byte) 0x0F, (byte) 0xC7, 
		(byte) 0xA4, (byte) 0xB0, (byte) 0x48, (byte) 0x26 };
	
	private static final String KEYGEN_ALGORITHM = "HmacSHA256";
	
	private static final int ITERATION_COUNT = 1000;
	
	private static final int KEY_LENGTH = 256;
	
	public static final String HMAC_KEY_ID = "BL-SC-Hmac-Cookie-Key";
	
	@Override
	public SecretKey generateKey(char[] password) {
		return generateKey(KEYGEN_ALGORITHM, password, SALT, ITERATION_COUNT,
				KEY_LENGTH);
	}

}
