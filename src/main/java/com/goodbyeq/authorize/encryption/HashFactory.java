package com.goodbyeq.authorize.encryption;

import java.security.MessageDigest;
import java.security.SecureRandom;
import java.util.Arrays;
import java.util.HashMap;
import java.util.NoSuchElementException;

import javax.crypto.Mac;
import javax.crypto.spec.SecretKeySpec;

import com.goodbyeq.util.Utils;


public class HashFactory 
{
	private static HashMap<String,Hash> registry = new HashMap<>();
	
	static 
	{
        registry.put("HmacSHA256", new PBKDF2HashedPassword(2000, "HmacSHA256"));
        registry.put("M:1", new RegularHash("SHA-256"));
		registry.put("X", new HMACSHA1HashedPassword());
	}

	
	public static Hash getInstance(String name)
	{
		Hash instance;
		
		instance = registry.get(name);
		if (instance == null)
		{
            throw new NoSuchElementException(String.format(
				"Algorithm name \"%s\" does not exist", 
				name));
		}
		
		return instance;
	}
	
	public interface Hash
	{
		public byte[] hash(byte[] key, byte[] data);
		public boolean match(byte[] key, byte[] data, byte[] hashData);
		public byte[] key();
        public int keySize();
	}

    public static class RegularHash implements Hash
    {
        private MessageDigest md;
        private int size;

        private RegularHash(String algorithm)
        {
            try {

                this.md = MessageDigest.getInstance(algorithm);

            } catch (Exception e) {

                throw new IllegalStateException(String.format(
                        "Execution failure: %s",
                        e.getMessage()),
                        e);
            }

            this.size = md.getDigestLength();
        }

        @Override
        public byte[] hash(byte[] key, byte[] data)
        {
            return performHash(key, data);
        }

        @Override
        public boolean match(byte[] key, byte[] data, byte[] hashData)
        {
            byte[] digest;

            if (hashData.length != this.size)
            {
                throw new IllegalArgumentException(String.format(
                        "Input data has wrong length for \"%s\" hash (%d != %d)",
                        this.md.getAlgorithm(),
                        hashData.length,
                        this.size));
            }

            digest = performHash(key, data);

            return Arrays.equals(hashData, digest);
        }

        @Override
        public byte[] key()
        {
            byte[] key;

            key = new byte[this.size];
            new SecureRandom().nextBytes(key);

            return key;
        }

        @Override
        public int keySize()
        {
            return this.size;
        }

        private byte[] performHash(byte[] key, byte[] data)
        {
            byte[] digest;

            try {

                this.md.reset();
                this.md.update(data);
                this.md.update(key);
                digest = this.md.digest();

            } catch (Exception e) {

                throw new IllegalStateException(String.format(
                        "Execution failure: %s",
                        e.getMessage()),
                        e);
            }

            return digest;
        }
    }
    
    public static class PBKDF2HashedPassword implements Hash
	{
		private int iterations = 500;
		
		private PBKDF2HashedPassword(int iterations, String name)
		{
			this.iterations = iterations;
		}

		@Override
		public byte[] hash(byte[] key, byte[] data)
		{
			byte[] salt;
			byte[] dk;

			salt = new byte[32];
			new SecureRandom().nextBytes(salt);

			dk = performHash(key, salt, data);

		    return Utils.concat(dk, salt);
		}

		@Override
		public boolean match(byte[] key, byte[] data, byte[] hashData)
		{
			byte[] salt;
			byte[] olddk;
			byte[] newdk;
			
			if (hashData.length != 64)
			{
				throw new IllegalArgumentException(String.format(
					"Input data has wrong length for hash and salt (%d != 64)", 
					hashData.length));
			}

			olddk = new byte[32];
			System.arraycopy(hashData, 0, olddk, 0, 32);
			salt = new byte[32];
			System.arraycopy(hashData, 32, salt, 0, 32);
			
			newdk = performHash(key, salt, data);
			
			return Arrays.equals(olddk, newdk);
		}

		@Override
		public byte[] key() 
		{
			byte[] key;

			key = new byte[32];
			new SecureRandom().nextBytes(key);
			
			return key;
		}

        @Override
        public int keySize() {
            return 32;
        }

        private byte[] performHash(byte[] key, byte[] salt, byte[] password)
		{
			MessageDigest md;
			byte[] digest;
			byte[] result;

			try {
				
				md = MessageDigest.getInstance("SHA-256");
				md.update(salt);
				md.update(key);
				digest = md.digest();
				result = PBKDF2.deriveKey(password, digest, this.iterations, 32);

			} catch (Exception e) {
				
				throw new IllegalStateException(String.format(
					"Execution failure: %s", 
					e.getMessage()), 
					e);
			}		
			return result;
		}
	}

    public static class MacHash implements Hash
    {
        private Mac mac;
        private int size;

        private MacHash(String algorithm)
        {
            try {

                this.mac = Mac.getInstance(algorithm);

            } catch (Exception e) {

                throw new IllegalStateException(String.format(
                        "Execution failure: %s",
                        e.getMessage()),
                        e);
            }

            this.size = this.mac.getMacLength();
        }

        @Override
        public byte[] hash(byte[] key, byte[] data)
        {
            return performHash(key, data);
        }

        @Override
        public boolean match(byte[] key, byte[] data, byte[] hashData)
        {
            byte[] digest;

            if (hashData.length != this.size)
            {
                throw new IllegalArgumentException(String.format(
                        "Input data has wrong length for \"%s\" hash (%d != %d)",
                        this.mac.getAlgorithm(),
                        hashData.length,
                        this.size));
            }

            digest = performHash(key, data);

            return Arrays.equals(hashData, digest);

        }

        @Override
        public byte[] key()
        {
            byte[] key;

            key = new byte[this.size];
            new SecureRandom().nextBytes(key);

            return key;
        }

        @Override
        public int keySize()
        {
            return this.size;
        }

        private byte[] performHash(byte[] key, byte[] data)
        {
            SecretKeySpec keyspec;
            byte[] digest;

            try {

                keyspec = new SecretKeySpec(key, mac.getAlgorithm());
                mac.init(keyspec);
                digest = mac.doFinal(data);

            } catch (Exception e) {

                throw new IllegalStateException(String.format(
                        "Execution failure: %s",
                        e.getMessage()),
                        e);
            }

            return digest;
        }

    }

    public static class HMACSHA1HashedPassword implements Hash
	{
		private HMACSHA1HashedPassword()
		{
		}
		
		@Override
		public byte[] hash(byte[] key, byte[] data)
		{
			throw new UnsupportedOperationException(
			    "Creating an HMAC/SHA1 hash is no longer supported");
		}

		@Override
		public boolean match(byte[] key, byte[] data, byte[] hashData)
		{
			byte[] username;
			int len;
			byte[] oldhash;
			byte[] newhash;
			SecretKeySpec keyspec;
			Mac mac;
			
			if (hashData.length <= 20)
			{
				throw new IllegalArgumentException(String.format(
					"Input data has wrong length for hash and salt (%d <= 20)", 
					hashData.length));
			}
			
			len = hashData.length - 20;
			oldhash = new byte[20];
			System.arraycopy(hashData, 0, oldhash, 0, 20);
			username = new byte[len];
			System.arraycopy(hashData, 20, username, 0, len);
			
		    try {
		    	
			    keyspec = new SecretKeySpec(username, "HmacSHA1");
                mac = Mac.getInstance("HmacSHA1");
		        mac.init(keyspec);
		        newhash = mac.doFinal(data);
		        
            } catch (Exception e) {
            	
				throw new IllegalStateException(String.format(
					"Execution failure: %s", 
					e.getMessage()), 
					e);
			}

			return Arrays.equals(oldhash, newhash);
		}

		@Override
		public byte[] key() 
		{
			throw new UnsupportedOperationException(
				"Creating an HMAC/SHA1 hash key is not supported");
		}

        @Override
        public int keySize() {

            throw new UnsupportedOperationException(
         				"Creating an HMAC/SHA1 hash keySize is not supported");
        }
    }
}
