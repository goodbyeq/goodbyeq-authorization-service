package com.goodbyeq.util;

import java.util.HashMap;
import java.util.Map;

import javax.annotation.Resource;
import javax.crypto.spec.SecretKeySpec;
import javax.servlet.http.Cookie;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

import org.apache.commons.codec.binary.Base64;
import org.apache.commons.lang3.StringUtils;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Component;

import com.goodbyeq.authorize.encryption.EncryptionFactory;
import com.goodbyeq.authorize.encryption.HashFactory;
import com.goodbyeq.authorize.encryption.KeyChainEntries;

/**
 * Created by abhiakey
 */
@Component(value="cookieManager")
public class CookieManager {
    private static final Logger LOG = LoggerFactory.getLogger(CookieManager.class);

    @Value(value = "${keychain.file}")
    private String keyChainFile;
    
    private static final String
            CHAR_SET = "UTF-8",
            TOKEN_VERSION = "v1",
            TOKEN_SEPARATOR = "|",
            PARSE_TOKEN_SEPARATOR = "\\|";

	@Resource(name = "keyChainEntries")
	private KeyChainEntries keyChainEntries;

    public void addCookie(HttpServletResponse response, String cookieName, String cookieValue, boolean isSecure, boolean isDeleted) {
        LOG.debug("addCookie {} isSecure {} isDelete {}", cookieName, isSecure, isDeleted);
        if(isDeleted) {
            LOG.debug("delete cookie {}", cookieName);
            Cookie deleteCookie = new Cookie(cookieName, "");
            deleteCookie.setMaxAge(0);
            deleteCookie.setPath("/");
            response.addCookie(deleteCookie);
            // delete existing cookie written w/o domain
            Cookie deleteCookie2 = new Cookie(cookieName, "");
            deleteCookie2.setMaxAge(0);
            deleteCookie2.setPath("/");
            response.addCookie(deleteCookie2);
        } else {
            Cookie finalCookie = new Cookie(cookieName, cookieValue);
            finalCookie.setMaxAge(-1);
            finalCookie.setHttpOnly(true);
            finalCookie.setSecure(isSecure);
            finalCookie.setPath("/");
            response.addCookie(finalCookie);
        }

    }
    
    public void addCookieWithMaxAge(HttpServletResponse response, String cookieName, String cookieValue, boolean isSecure, boolean isDeleted, int maxAge) {
        LOG.debug("addCookie {} isSecure {} isDelete {}", cookieName, isSecure, isDeleted);
        if(isDeleted) {
            LOG.debug("delete cookie {}", cookieName);
            Cookie deleteCookie = new Cookie(cookieName, "");
            deleteCookie.setMaxAge(0);
            deleteCookie.setPath("/");
            response.addCookie(deleteCookie);
            // delete existing cookie written w/o domain
            Cookie deleteCookie2 = new Cookie(cookieName, "");
            deleteCookie2.setMaxAge(0);
            deleteCookie2.setPath("/");
            response.addCookie(deleteCookie2);

        } else {
            Cookie finalCookie = new Cookie(cookieName, cookieValue);
            finalCookie.setMaxAge(maxAge);
            finalCookie.setHttpOnly(true);
            finalCookie.setSecure(isSecure);
            finalCookie.setPath("/");
            response.addCookie(finalCookie);
        }

    }

    public String encryptCookieContent(Map<String, String> cookieContent) {
        try {
            StringBuilder cookieRawInput = new StringBuilder();
            for(Map.Entry<String, String> entry : cookieContent.entrySet()) {
                if (cookieRawInput.toString().length()>0) {
                    cookieRawInput.append(",");
                }
                cookieRawInput.append(entry.getKey() + "=" + entry.getValue());
            }
            LOG.debug("encrypt cookie contents {}", cookieRawInput.toString());
    		
    		byte[] encryptionKey = keyChainEntries.getAesKeyBytes();	
        	SecretKeySpec secretKey = new SecretKeySpec(encryptionKey, AuthorizationServiceConstants.AES);
			EncryptionFactory.Encryption enc = EncryptionFactory.getInstance(secretKey.getAlgorithm());
            byte[] encBytes = enc.encrypt(secretKey.getEncoded(), cookieRawInput.toString().getBytes(CHAR_SET));
            String encString = Base64.encodeBase64URLSafeString(encBytes);
            LOG.debug("generate cookie encString {}", encString);
            
            // MAC
    		byte[] hashKey = keyChainEntries.getHashKeyBytes();
    		SecretKeySpec secretKeyMac = new SecretKeySpec(hashKey, AuthorizationServiceConstants.HMACSHA256);
        	HashFactory.Hash mac = HashFactory.getInstance(secretKeyMac.getAlgorithm());
            byte[] macBytes = mac.hash(secretKeyMac.getEncoded(), encBytes);
            String macString = Base64.encodeBase64URLSafeString(macBytes);
            LOG.debug("generate cookie value {}", macString);

            StringBuilder builder = new StringBuilder();
            builder.append(TOKEN_VERSION);
            builder.append(TOKEN_SEPARATOR);
            builder.append(encString);
            builder.append(TOKEN_SEPARATOR);
            builder.append(macString);
            return builder.toString();
        } catch (Exception ex) {
            LOG.error("encrypt cookie exception: {}", ex.getMessage());
            ex.printStackTrace();
            return null;
        }
    }
    
    
    public Map<String, String> getExistingCookie(HttpServletRequest request, HttpServletResponse response, String cookieName) {
        LOG.debug("Get cookie [{}] started", cookieName);
        try {
            String cookieValue = getCookie(request, cookieName);
            if (StringUtils.isEmpty(cookieValue)) {
                LOG.debug("cookie {} does not exist", cookieName);
                return null;
            }
            String[] part = cookieValue.split(PARSE_TOKEN_SEPARATOR);
            if ( part.length != 3 || !part[0].equals(TOKEN_VERSION) ) {
                LOG.error("Validate cookie {} value: {} length {} and part {}",
                        cookieName, " length and version mismatch", part.length, part);
                return null;
            }
            
            byte[] encBytes = Base64.decodeBase64(part[1]);
            byte[] macBytes = Base64.decodeBase64(part[2]);
            
            byte[] encryptionKey = keyChainEntries.getAesKeyBytes();
    		byte[] hashKey = keyChainEntries.getHashKeyBytes();
    		
            SecretKeySpec macKey = new SecretKeySpec(hashKey, AuthorizationServiceConstants.HMACSHA256);
            HashFactory.Hash mac = HashFactory.getInstance(macKey.getAlgorithm());
            if (!mac.match(macKey.getEncoded(), encBytes, macBytes)) {
                LOG.error("Validate cookie {} value: {}", cookieName, " mac mismatch");
                return null;
            }
            SecretKeySpec encKey = new SecretKeySpec(encryptionKey, AuthorizationServiceConstants.AES);
            EncryptionFactory.Encryption enc = EncryptionFactory.getInstance(encKey.getAlgorithm());
            byte[] idBytes = enc.decrypt(encKey.getEncoded(), encBytes);
            String cookieContent = new String(idBytes, CHAR_SET);
            LOG.debug("Get cookie value {}", cookieContent);

            Map<String, String> pairs = new HashMap<>();
            String[] cookieContentsPairs = cookieContent.split(",");
            for (String pair:cookieContentsPairs) {
                String[] nameVal = pair.split("=");
                pairs.put(nameVal[0],nameVal[1]);
            }
            LOG.debug("Get cookie contents {}", pairs);
            return pairs;
        } catch (Exception ex) {
            LOG.error("Validate cookie {} exception: {}", cookieName, ex.getMessage());
            ex.printStackTrace();
            return null;
        }
    }
    
    public String getCookie(HttpServletRequest request, final String cookieName) {
        LOG.debug("Get cookie {}", cookieName);
        String cookieValue = "";
        try {
            Cookie[] cookies = request.getCookies();
            if (cookies == null || cookies.length < 1) {
                return cookieValue;
            }
            for (Cookie cookie : cookies) {
                if (StringUtils.equalsIgnoreCase(cookieName, cookie.getName())) {
                    cookieValue = cookie.getValue();
                    break;
                }
            }
        } catch (Exception ex) {
            LOG.error("Get cookie {} error: {}", cookieName, ex.getMessage());
            ex.printStackTrace();
        }
        LOG.debug("Get cookie {} value: {}", cookieName, cookieValue);
        return cookieValue;
    }

    
}
