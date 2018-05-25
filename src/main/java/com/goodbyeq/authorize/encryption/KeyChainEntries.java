package com.goodbyeq.authorize.encryption;

import java.util.List;

import com.goodbyeq.authorize.encryption.KeyChain.KeyEntry;
import com.goodbyeq.util.AuthorizationServiceConstants;

public class KeyChainEntries {
	
	private List<KeyEntry> keyEntries;
	private byte[] aesKeyBytes;
	private byte[] hashKeyBytes;

	public List<KeyEntry> getKeyEntries() {
		return keyEntries;
	}

	public void setKeyEntries(List<KeyEntry> keyEntries) {
		this.keyEntries = keyEntries;
		for(KeyEntry entry : keyEntries){
			if(entry != null){
				if(AuthorizationServiceConstants.AES.equalsIgnoreCase(entry.getAlgorithm())){
					setAesKeyBytes(entry.getKeyBytes());
				}else if(AuthorizationServiceConstants.HMACSHA256.equalsIgnoreCase(entry.getAlgorithm())){
					setHashKeyBytes(entry.getKeyBytes());
				}
			}
		}
	}
	
	public byte[] getAesKeyBytes() {
		return aesKeyBytes;
	}

	public void setAesKeyBytes(byte[] aesKeyBytes) {
		this.aesKeyBytes = aesKeyBytes;
	}

	public byte[] getHashKeyBytes() {
		return hashKeyBytes;
	}

	public void setHashKeyBytes(byte[] hashKeyBytes) {
		this.hashKeyBytes = hashKeyBytes;
	}

	public byte[] getKeyBytes(String algorithm){
		if(AuthorizationServiceConstants.AES.equalsIgnoreCase(algorithm)){
			return getAesKeyBytes();
		}else if(AuthorizationServiceConstants.HMACSHA256.equalsIgnoreCase(algorithm)){
			return getHashKeyBytes();
		}
		return null;
	}
}
