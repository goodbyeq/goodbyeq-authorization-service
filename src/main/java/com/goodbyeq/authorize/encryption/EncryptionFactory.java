package com.goodbyeq.authorize.encryption;

import java.security.SecureRandom;
import java.util.HashMap;
import java.util.NoSuchElementException;

import javax.crypto.Cipher;
import javax.crypto.SecretKey;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;

import com.goodbyeq.util.Utils;


public class EncryptionFactory 
{
	private static HashMap<String,Encryption> registry = new HashMap<>();
	
	static 
	{
        registry.put("AES", new AESEncryption());
	}
	
	public static Encryption getInstance(String name)
	{
		Encryption instance;
		
		instance = registry.get(name);
		if (instance == null)
		{
            throw new NoSuchElementException(String.format(
				"Algorithm name \"%s\" does not exist", 
				name));
		}
		
		return instance;
	}
	
	public interface Encryption
	{
		public byte[] encrypt(byte[] key, byte[] rawData);
		public byte[] decrypt(byte[] key, byte[] encryptedData);
		public byte[] key();
        public int    keySize();
	}

    // Algorithm "Z:1" is "AES-256" encryption (32 byte key)
    // with "CBC" block mode and "PKCS5" padding.  The encrypted data
    // has a 16 byte IV appended

    public static class AESEncryption implements Encryption
	{
		private AESEncryption()
		{
		}

		@Override
		public byte[] encrypt(byte[] key, byte[] rawData) 
		{
			byte[] iv;
			IvParameterSpec ivspec;
			SecretKey aesKey;
			Cipher cipher;
			byte[] ciphertext;
			
			if (key.length != 32)
			{
				throw new IllegalArgumentException(String.format(
					"Input key has wrong length (%d != 32)", 
					key.length));
			}

			iv = new byte[16];
			new SecureRandom().nextBytes(iv);
			ivspec = new IvParameterSpec(iv);
			aesKey = new SecretKeySpec(key, "AES");
			
			try {
			    cipher = Cipher.getInstance("AES/CBC/PKCS5Padding");
			    cipher.init(Cipher.ENCRYPT_MODE, aesKey, ivspec);
			    ciphertext = cipher.doFinal(rawData);
			} catch (Exception e) {
				throw new IllegalStateException(String.format(
					"Execution failure: %s", 
					e.getMessage()), 
					e);
			}
		
		    return Utils.concat(ciphertext, iv);
		}

		@Override
		public byte[] decrypt(byte[] key, byte[] encryptedData) 
		{
			int len;
			byte[] iv;
			byte[] ciphertext;
			IvParameterSpec ivspec;
			SecretKey aesKey;
			Cipher cipher;
			byte[] cleartext;
			
			if (key.length != 32)
			{
				throw new IllegalArgumentException(String.format(
					"Input key has wrong length (%d != 32)", 
					key.length));
			}

			if (encryptedData.length <= 16)
			{
				throw new IllegalArgumentException(String.format(
					"Encrypted input data too short to contain IV (%d <= 16)", 
					encryptedData.length));
			}
			
			len = encryptedData.length - 16;
			ciphertext = new byte[len];
			System.arraycopy(encryptedData, 0, ciphertext, 0, len);
			iv = new byte[16];
			System.arraycopy(encryptedData, len, iv, 0, 16);
			ivspec = new IvParameterSpec(iv);
			aesKey = new SecretKeySpec(key, "AES");

			try {
				
			    cipher = Cipher.getInstance("AES/CBC/PKCS5Padding");
			    cipher.init(Cipher.DECRYPT_MODE, aesKey, ivspec);
			    cleartext = cipher.doFinal(ciphertext);
			    
			} catch (Exception e) {
				
				throw new IllegalStateException(String.format(
					"Execution failure: %s", 
					e.getMessage()), 
					e);
			}
			
			return cleartext;
		}

		@Override
		public byte[] key() 
		{
			byte[] key = new byte[32];

			new SecureRandom().nextBytes(key);
			
			return key;
		}

        @Override
        public int keySize() {
            return 32;
        }
    }

    // Legacy algorithm "AES" is "AES-128" encryption (16 byte key)
    // with "CBC" block mode and "PKCS5" padding.  The encrypted data
    // has a 16 byte IV prepended
    public static class LegacyAESEncryption implements Encryption
    {
        private LegacyAESEncryption()
        {
        }

        @Override
        public byte[] encrypt(byte[] key, byte[] rawData)
        {
            byte[] iv;
            IvParameterSpec ivspec;
            SecretKey aesKey;
            Cipher cipher;
            byte[] ciphertext;

            if (key.length != 16)
            {
                throw new IllegalArgumentException(String.format(
                        "Input key has wrong length (%d != 16)",
                        key.length));
            }

            iv = new byte[16];
            new SecureRandom().nextBytes(iv);
            ivspec = new IvParameterSpec(iv);
            aesKey = new SecretKeySpec(key, "AES");

            try {
                cipher = Cipher.getInstance("AES/CBC/PKCS5Padding");
                cipher.init(Cipher.ENCRYPT_MODE, aesKey, ivspec);
                ciphertext = cipher.doFinal(rawData);
            } catch (Exception e) {
                throw new IllegalStateException(String.format(
                        "Execution failure: %s",
                        e.getMessage()),
                        e);
            }

            return Utils.concat(iv, ciphertext);
        }

        @Override
        public byte[] decrypt(byte[] key, byte[] encryptedData)
        {
            int len;
            byte[] iv;
            byte[] ciphertext;
            IvParameterSpec ivspec;
            SecretKey aesKey;
            Cipher cipher;
            byte[] cleartext;

            if (key.length != 16)
            {
                throw new IllegalArgumentException(String.format(
                        "Input key has wrong length (%d != 16)",
                        key.length));
            }

            if (encryptedData.length <= 16)
            {
                throw new IllegalArgumentException(String.format(
                        "Encrypted input data too short to contain IV (%d <= 16)",
                        encryptedData.length));
            }

            len = encryptedData.length - 16;
            ciphertext = new byte[len];
            System.arraycopy(encryptedData, 16, ciphertext, 0, len);
            iv = new byte[16];
            System.arraycopy(encryptedData, 0, iv, 0, 16);
            ivspec = new IvParameterSpec(iv);
            aesKey = new SecretKeySpec(key, "AES");

            try {

                cipher = Cipher.getInstance("AES/CBC/PKCS5Padding");
                cipher.init(Cipher.DECRYPT_MODE, aesKey, ivspec);
                cleartext = cipher.doFinal(ciphertext);

            } catch (Exception e) {

                throw new IllegalStateException(String.format(
                        "Execution failure: %s",
                        e.getMessage()),
                        e);
            }

            return cleartext;
        }

        @Override
        public byte[] key()
        {
            byte[] key = new byte[16];

            new SecureRandom().nextBytes(key);

            return key;
        }

        @Override
        public int keySize() {
            return 16;
        }
    }
}
