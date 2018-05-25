package com.goodbyeq.authorize.encryption;

import java.io.FileInputStream;
import java.io.FileNotFoundException;
import java.io.InputStream;
import java.io.UnsupportedEncodingException;
import java.security.Key;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.NoSuchElementException;

import javax.crypto.KeyGenerator;
import javax.crypto.spec.SecretKeySpec;
import javax.xml.XMLConstants;
import javax.xml.parsers.DocumentBuilder;
import javax.xml.parsers.DocumentBuilderFactory;

import org.apache.commons.codec.binary.Base64;
import org.apache.commons.lang3.StringUtils;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.stereotype.Component;
import org.w3c.dom.Document;
import org.w3c.dom.Element;
import org.w3c.dom.NodeList;

import com.goodbyeq.exception.CryptoException;
import com.goodbyeq.exception.KeyNotFoundException;

/**
 * @author vakey
 *
 */

@Component("keyChain")
public class KeyChain {

	private static final String CLASSPATH_PREFIX = "CLASSPATH/";
	private static final String SPRING_CLASSPATH_PREFIX = "classpath:/";

	private static final String BLUE_GENERATE = "BLUE";
	private static final int KEY_SIZE = 32;

	private static Logger log = LoggerFactory.getLogger(KeyChain.class);

	protected Map<String, KeyName> nameMap = new HashMap<String, KeyName>();

	/**
	 * Create an empty keychain.
	 * 
	 * @throws CryptoException
	 */
	public KeyChain() throws CryptoException {
	}

	/**
	 * Load key-chain from an input stream
	 * 
	 * @param stream
	 * @throws CryptoException
	 */
	public KeyChain(InputStream stream) throws CryptoException {
		loadKeyChain(stream);
	}

	/**
	 * Load key-chain from a XML file. The file can be an absolute path or
	 * prefixed with CLASSPATH for files in class path.
	 * 
	 * @param fileName
	 *            The XML Key-chain file
	 * @throws CryptoException
	 */
	public KeyChain(String fileName) throws CryptoException {

		try {
			InputStream stream;

			if (fileName.startsWith(CLASSPATH_PREFIX) || fileName.startsWith("/" + CLASSPATH_PREFIX)) {
				ClassLoader classLoader = Thread.currentThread().getContextClassLoader();

				if (classLoader == null) {
					classLoader = getClass().getClassLoader();
				}

				int i = fileName.indexOf(CLASSPATH_PREFIX);
				String name = fileName.substring(i + CLASSPATH_PREFIX.length());

				stream = classLoader.getResourceAsStream(name);
			} else {
				stream = new FileInputStream(fileName);
			}
			loadKeyChain(stream);
		} catch (FileNotFoundException e) {
			throw new CryptoException("File '" + fileName + "' not found: " + e.getMessage(), e);
		}
	}

	/**
	 * Load key-chain from file, handling either xml or base64 encoded encrypted
	 * file
	 *
	 * @param fileName
	 *            for key file, either as xml, or base64 encoded encrypted
	 * @param awsKmsClient
	 *            kms client used to decrypt key if file is encrypted
	 * @throws CryptoException
	 *//*
	public KeyChain(String fileName, AwsKmsClient awsKmsClient) throws CryptoException {

		try {
			InputStream stream;

			String cpPrefix = getClasspathPrefix(fileName);

			log.debug("have classpath prefix={}", cpPrefix);

			if (cpPrefix != null) {
				ClassLoader classLoader = Thread.currentThread().getContextClassLoader();

				if (classLoader == null) {
					classLoader = getClass().getClassLoader();
				}

				int i = fileName.indexOf(cpPrefix);
				String name = fileName.substring(i + cpPrefix.length());

				log.debug("loading file {} from classpath", fileName);
				stream = classLoader.getResourceAsStream(name);
			} else {
				log.debug("loading file {} using path", fileName);
				stream = new FileInputStream(fileName);
			}
			init(stream, awsKmsClient);
		} catch (FileNotFoundException e) {
			throw new CryptoException("File '" + fileName + "' not found: " + e.getMessage(), e);
		}
	}

	*//**
	 * Load key-chain from file which is an input stream
	 *
	 * @param file
	 *            file as an input stream
	 * @param awsKmsClient
	 *            kms client used to decrypt key if file is encrypted
	 * @throws CryptoException
	 *//*
	public KeyChain(InputStream file, AwsKmsClient awsKmsClient) throws CryptoException {
		init(file, awsKmsClient);
	}

	*//**
	 * Load key-chain from file which is a String
	 *
	 * @param awsKmsClient
	 *            kms client used to decrypt key if file is encrypted
	 * @param file
	 *            file as a String
	 * @throws CryptoException
	 *//*
	public KeyChain(AwsKmsClient awsKmsClient, String file) throws CryptoException {

		InputStream keyChainFileAsStream = new ByteArrayInputStream(file.getBytes(StandardCharsets.UTF_8));
		init(keyChainFileAsStream, awsKmsClient);
	}

	private String getClasspathPrefix(String fileName) {
		if (fileName.startsWith(CLASSPATH_PREFIX) || fileName.startsWith("/" + CLASSPATH_PREFIX)) {
			return CLASSPATH_PREFIX;
		}

		if (fileName.startsWith(SPRING_CLASSPATH_PREFIX) || fileName.startsWith("/" + SPRING_CLASSPATH_PREFIX)) {
			return SPRING_CLASSPATH_PREFIX;
		}

		return null;
	}

	private void init(InputStream stream, AwsKmsClient awsKmsClient) throws CryptoException {
		boolean isXml = false;
		String data;

		try {

			data = IOUtils.toString(stream, "UTF-8");
			if (data.contains("<")) {
				log.debug("detected xml in stream");
				isXml = true;
				// we need to re-create since toString drains the stream
				stream = new ByteArrayInputStream(data.getBytes("UTF-8"));
			}

		} catch (IOException e) {
			throw new CryptoException(e);
		}

		if (isXml) {
			log.debug("loading xml");
			loadKeyChain(stream);
		} else {
			log.debug("loading encrypted");

			if (data.contains("|")) {
				log.debug("loading old");
				legacyFormatDecrypt(data, awsKmsClient);
			} else {
				log.debug("loading new");
				newFormatDecrypt(data, awsKmsClient);
			}
		}

		if (awsKmsClient != null) {
			awsKmsClient.close();
		}
	}

	private void legacyFormatDecrypt(String data, AwsKmsClient awsKmsClient) throws CryptoException {
		String[] parts = data.split("\\|");

		if (parts.length != 2) {
			throw new CryptoException("stream is invalid, expected 2 parts, but got parts=" + parts.length);
		}

		awsKmsClient.start();

		byte[] decodedKey = Base64.decodeBase64(parts[0]);
		byte[] key = awsKmsClient.decrypt(decodedKey);

		EncryptionFactory.Encryption aesEncryption = EncryptionFactory.getInstance("Z:1");

		byte[] decodedFile = Base64.decodeBase64(parts[1]);
		byte[] keyFile = aesEncryption.decrypt(key, decodedFile);

		loadKeyChain(new ByteArrayInputStream(keyFile));
	}

	private void newFormatDecrypt(String data, AwsKmsClient awsKmsClient) throws CryptoException {
		String[] parts = data.split("\\!");

		if (parts.length != 2) {
			throw new CryptoException("stream is invalid, expected 2 parts, but got parts=" + parts.length);
		}

		byte[] controlHeader = Base64.decodeBase64(parts[0]);

		byte[] controlHeaderMask = getControlHeaderMask(controlHeader.length);

		ByteBuffer byteBuffer = ByteBuffer.wrap(Utils.maskBytes(controlHeaderMask, controlHeader));

		int awsLength = byteBuffer.getInt();
		int bodyLength = byteBuffer.getInt();

		int awsBlocks = (awsLength + 63) / 64;
		int bodyBlocks = (bodyLength + 63) / 64;

		String[] bodyParts = new String[awsBlocks + bodyBlocks];

		char[] block = new char[64];

		for (int j = 0, i = 0; j < (awsBlocks + bodyBlocks); i += 64, ++j) {
			System.arraycopy(parts[1].toCharArray(), i, block, 0, 64);
			bodyParts[j] = new String(block);
		}

		StringBuilder aws = new StringBuilder();
		for (int i = 0; i < awsBlocks; ++i) {
			int offset = byteBuffer.getInt();
			aws.append(bodyParts[offset]);
		}

		StringBuilder body = new StringBuilder();
		for (int i = 0; i < bodyBlocks; ++i) {
			int offset = byteBuffer.getInt();
			body.append(bodyParts[offset]);
		}

		awsKmsClient.start();

		byte[] key = awsKmsClient.decrypt(Base64.decodeBase64(aws.substring(0, awsLength)));

		EncryptionFactory.Encryption aesEncryption = EncryptionFactory.getInstance("Z:1");

		byte[] decodedFile = Base64.decodeBase64(body.substring(0, bodyLength));
		byte[] keyFile = aesEncryption.decrypt(key, decodedFile);

		loadKeyChain(new ByteArrayInputStream(keyFile));
	}*/

	/**
	 * Given a key name, get the current key version.
	 * 
	 * @param name
	 *            The name of the key.
	 * @return The current version of the key.
	 */
	public int getCurrentKeyVersion(String name) throws KeyNotFoundException {
		// Find key name first

		KeyName keyName = nameMap.get(name);

		if (keyName == null)
			throw new KeyNotFoundException("Key name '" + name + "' is not defined.");

		return keyName.currentVersion;
	}

	/**
	 * Given a key name and version, return the key.
	 * 
	 * @param name
	 *            The name of the key.
	 * @param version
	 *            The version of key.
	 * @return The KeySpec object for the key.
	 */
	public SecretKeySpec getKey(String name, int version) throws KeyNotFoundException {

		KeyEntry keyEntry = getKeyEntry(name, version);
		SecretKeySpec key = new SecretKeySpec(keyEntry.keyBytes, keyEntry.algorithm);

		return key;
	}

	/**
	 * Given a key name and version, return the passphrase.
	 * 
	 * @param name
	 *            The name of the key.
	 * @param version
	 *            The version of key.
	 * @return The passphrase with spaces trimmed.
	 */
	public String getPassphrase(String name, int version) throws KeyNotFoundException {
		KeyEntry keyEntry = getKeyEntry(name, version);
		return keyEntry.passphrase;
	}

	/**
	 * Given a key name and version, return the key bytes. The byte array is the
	 * binary key material. The size varies depending on the algorithm.
	 * 
	 * @param name
	 *            The name of the key, default is "login".
	 * @param version
	 *            The version of key.
	 * @return The byte array for the key material.
	 */
	public byte[] getKeyBytes(String name, int version) throws KeyNotFoundException {
		KeyEntry keyEntry = getKeyEntry(name, version);
		return keyEntry.keyBytes;
	}

	public void addKey(String name, int version, String algorithm, String passphrase) throws CryptoException {

		KeyName keyName = nameMap.get(name);
		if (keyName == null) {
			keyName = new KeyName(name);
			nameMap.put(name, keyName);
		}

		KeyEntry keyEntry = new KeyEntry(name, version, algorithm, passphrase);
		keyName.addKey(keyEntry);
	}

	/**
	 * Given a key name and version, return the key entry. This is used by
	 * KeyManager so can't be private.
	 * 
	 * @param name
	 *            The name of the key, default is "login".
	 * @param version
	 *            The version of key.
	 * @return KeyEntry object.
	 */
	KeyEntry getKeyEntry(String name, int version) throws KeyNotFoundException {
		// Find key name first

		KeyName keyName = nameMap.get(name);

		if (keyName == null)
			throw new KeyNotFoundException("Key name '" + name + "' is not defined.");

		KeyEntry keyEntry = keyName.versionMap.get(Integer.valueOf(version));

		if (keyEntry == null)
			throw new KeyNotFoundException("Key version " + version + " is not defined for name '" + name + "'.");

		return keyEntry;
	}

	/**
	 * Parse the keychain and load the keys from the input stream. This call is
	 * typically made from Servlet init method, like this
	 * 
	 * <pre>
	 * String keyFile = Config.getValue("idp.keychain", "WEB-INF/key.xml");
	 * KeyManager.loadKey(servletConfig.getServletContext().getResourceAsStream(keyFile));
	 * </pre>
	 * 
	 * 
	 * @param is
	 *            InputStream for the keychain file
	 * @return 
	 * @throws CryptoException
	 */
	public KeyChainEntries loadKeyChain(InputStream is) throws CryptoException {
		Document doc;
		KeyChainEntries keyChainEntries = new KeyChainEntries();
		try {
			DocumentBuilderFactory dbFactory = DocumentBuilderFactory.newInstance();

			dbFactory.setFeature(XMLConstants.FEATURE_SECURE_PROCESSING, true);
			dbFactory.setNamespaceAware(true);

			DocumentBuilder docBuilder = dbFactory.newDocumentBuilder();
			doc = docBuilder.parse(is);

		} catch (Exception e) {
			log.error("Error reading key from stream " + is);
			throw new CryptoException("Error reading key from stream: " + e.getMessage(), e);
		}

		Element root = doc.getDocumentElement();

		// Make sure root node is "key-chain"

		String localName;

		if (root == null || (localName = root.getLocalName()) == null || !localName.equals("key-chain")) {
			throw new CryptoException("Wrong XML file. Root node is not key-chain.");
		}

		try {

			// Get <key-name> entries

			NodeList nameList = root.getElementsByTagName("key-name");

			if ((nameList == null) || (nameList.getLength() <= 0)) {
				throw new CryptoException("Empty key file.");
			}

			List<KeyEntry> keyEntries = new ArrayList<KeyEntry>();
			
			for (int i = 0; i < nameList.getLength(); i++) {
				Element nameElement = (Element) nameList.item(i);
				String name = nameElement.getAttribute("name");

				NodeList keyList = nameElement.getElementsByTagName("key-spec");

				if ((keyList == null) || (keyList.getLength() <= 0)) {
					log.warn("Key " + name + " doesn't have entries, ignored.");
					break;
				}

				// Create name entry

				KeyName keyName = new KeyName(name);
				nameMap.put(name, keyName);
				for (int j = 0; j < keyList.getLength(); j++) {
					Element keyElement = (Element) keyList.item(j);

					int version = 0;
					String versionStr = keyElement.getAttribute("version");

					try {
						if (versionStr != null)
							version = Integer.parseInt(versionStr);
					} catch (NumberFormatException e) {
					} // Ignore NumberFormatException

					// Check if version exists

					if (keyName.versionMap.get(version) != null) {
						log.warn("Duplicate version " + version + "for key " + name + ", old one is overwritten.");
					}

					String algorithm = keyElement.getAttribute("algorithm");

					String passphrase = StringUtils.strip(keyElement.getTextContent());

					KeyEntry keyEntry = new KeyEntry(name, version, algorithm, passphrase);
					keyEntries.add(keyEntry);
					keyName.addKey(keyEntry);
				}
			}
			keyChainEntries.setKeyEntries(keyEntries);
		} catch (NullPointerException e) {
			throw new CryptoException("Null field in key.xml: " + e.getMessage(), e);
		} catch (Exception e) {
			throw new CryptoException("XML parsing error: " + e.getMessage(), e);
		}
		return keyChainEntries;
	}

	public void addKeyDirect(String name, int version, String algorithm, String generate, String passPhraseSeed)
			throws CryptoException {

		String passphrase = Base64
				.encodeBase64URLSafeString(generateKeyBytes(name, version, algorithm, passPhraseSeed, 32));

		KeyEntry keyEntry = new KeyEntry(name, version, algorithm, passphrase);

		KeyName keyName = new KeyName(name);
		nameMap.put(name, keyName);
		keyName.addKey(keyEntry);
	}

	/**
	 * Genereate key material from passphrase. The name and version are used as
	 * the salt.
	 * 
	 * @param name
	 * @param version
	 * @param algorithm
	 * @param password
	 * @return The key byte array.
	 * @throws CryptoException
	 */
	public byte[] generateKeyBytes(String name, int version, String algorithm, String password) throws CryptoException {
		return generateKeyBytes(name, version, algorithm, password, 0);
	}

	public byte[] generateKeyBytes(String name, int version, String algorithm, String password, int size)
			throws CryptoException {

		int keySize = getAlgoSize(size, algorithm);
		keySize = (keySize == 0) ? KEY_SIZE : keySize;

		byte[] keyBytes = null;

		try {
			// Use key name + version string as the salt
			String salt = name + version;

			keyBytes = generateDerivedKey(keySize, password.getBytes("UTF-8"), salt.getBytes("UTF-8"));

		} catch (UnsupportedEncodingException e) {
			throw new CryptoException("Unsupported encoding in password/key name", e);
		}

		return keyBytes;
	}

	private static int getAlgoSize(int size, String algorithm) throws CryptoException {
		int keySize = 0;
		Key testKey = null;

		if (size > 0) {
			return size;
		}

		// try our proprietary first
		try {
			keySize = HashFactory.getInstance(algorithm).keySize();
		} catch (NoSuchElementException e) {
			try {
				keySize = EncryptionFactory.getInstance(algorithm).keySize();
			} catch (NoSuchElementException e1) {
			}
		}

		try {
			if (keySize == 0) {
				KeyGenerator generator = KeyGenerator.getInstance(algorithm);
				testKey = generator.generateKey();

				keySize = testKey.getEncoded().length;
			}
		} catch (NoSuchAlgorithmException e) {
			throw new CryptoException("Provider doesn't support algortihm: " + algorithm, e);
		}

		return keySize;
	}

	/**
	 * the derived key function, the ith hash of the password and the salt. This
	 * is copied from BC's implemenation of OpenSSL PBE key.
	 * 
	 */
	public byte[] generateDerivedKey(int bytesNeeded, byte[] password, byte[] salt) throws CryptoException {
		return generateKey("SHA-256", bytesNeeded, password, salt);
	}

	public byte[] generateKey(String digest, int bytesNeeded, byte[] password, byte[] salt) throws CryptoException {
		byte[] key = new byte[bytesNeeded];

		try {
			MessageDigest md = MessageDigest.getInstance(digest);

			int offset = 0;
			byte[] hash = null;

			for (;;) {
				md.update(password);
				md.update(salt);
				hash = md.digest();

				int len = (bytesNeeded > hash.length) ? hash.length : bytesNeeded;
				System.arraycopy(hash, 0, key, offset, len);
				offset += len;

				// check if we need any more
				bytesNeeded -= len;
				if (bytesNeeded == 0) {
					break;
				}

				// do another round
				md.update(hash);
			}

			return key;
		} catch (NoSuchAlgorithmException e) {
			throw new CryptoException("Provider doesn't support " + digest + ": " + e.getMessage(), e);
		}
	}

	// Nested classes

	private static class KeyName {
		public String name;
		public int currentVersion;

		Map<Integer, KeyEntry> versionMap;

		public KeyName(String name) {
			this.name = name;
			currentVersion = 0;
			versionMap = new HashMap<Integer, KeyEntry>();
		}

		public void addKey(KeyEntry entry) {
			if (entry.version > currentVersion)
				currentVersion = entry.version;
			versionMap.put(new Integer(entry.version), entry);
		}
	}

	class KeyEntry {
		public String name;
		public int version;
		public String algorithm;
		public String passphrase;
		public byte[] keyBytes;

		public KeyEntry(String name, int version, String algorithm, String passphrase) throws CryptoException {
			this.name = name;
			this.version = version;
			this.algorithm = algorithm;
			this.passphrase = passphrase;
			keyBytes = generateKeyBytes(name, version, algorithm, passphrase, 0);
		}

		public String getName() {
			return name;
		}

		public void setName(String name) {
			this.name = name;
		}

		public int getVersion() {
			return version;
		}

		public void setVersion(int version) {
			this.version = version;
		}

		public String getAlgorithm() {
			return algorithm;
		}

		public void setAlgorithm(String algorithm) {
			this.algorithm = algorithm;
		}

		public String getPassphrase() {
			return passphrase;
		}

		public void setPassphrase(String passphrase) {
			this.passphrase = passphrase;
		}

		public byte[] getKeyBytes() {
			return keyBytes;
		}

		public void setKeyBytes(byte[] keyBytes) {
			this.keyBytes = keyBytes;
		}
	}

}
