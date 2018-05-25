package com.goodbyeq.user.service.impl;

import java.io.UnsupportedEncodingException;
import java.security.SecureRandom;
import java.util.HashMap;
import java.util.Map;
import java.util.UUID;

import javax.annotation.Resource;
import javax.crypto.spec.SecretKeySpec;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

import org.apache.commons.codec.binary.Base64;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Propagation;
import org.springframework.transaction.annotation.Transactional;
import org.springframework.ui.ModelMap;
import org.springframework.util.StringUtils;

import com.goodbyeq.authorization.framework.SecureHasher;
import com.goodbyeq.authorize.encryption.EncryptionFactory;
import com.goodbyeq.authorize.encryption.HashFactory;
import com.goodbyeq.authorize.encryption.HashFactory.Hash;
import com.goodbyeq.authorize.encryption.KeyChainEntries;
import com.goodbyeq.exception.GBQUserException;
import com.goodbyeq.user.bo.GBQUserDTO;
import com.goodbyeq.user.dao.api.UserDAO;
import com.goodbyeq.user.db.bo.UserVO;
import com.goodbyeq.user.service.api.GBQUserService;
import com.goodbyeq.user.service.api.UserService;
import com.goodbyeq.util.AuthorizationServiceConstants;
import com.goodbyeq.util.CookieManager;

@Service("userService")
@Transactional(propagation = Propagation.SUPPORTS)
public class UserServiceImpl implements UserService {
	private static final Logger logger = LoggerFactory.getLogger(UserServiceImpl.class);

	@Autowired
	private UserDAO userDAO;

	@Autowired
	private GBQUserService gbqUserService;

	private static String COOKIE_NAME = "GBQ_C";

	@Resource(name = "cookieManager")
	private CookieManager cookieManager;

	private static final byte[] KEY = { (byte) 0x1C, (byte) 0x33, (byte) 0x18, (byte) 0x63, (byte) 0xC8, (byte) 0xA4,
			(byte) 0x3F, (byte) 0xD2, (byte) 0x30, (byte) 0x08, (byte) 0x0F, (byte) 0xC7, (byte) 0xA4, (byte) 0xB0,
			(byte) 0x48, (byte) 0x26 };

	public UserDAO getUserDAO() {
		return userDAO;
	}

	public void setUserDAO(UserDAO userDAO) {
		this.userDAO = userDAO;
	}

	public GBQUserService getGbqUserService() {
		return gbqUserService;
	}

	public void setGbqUserService(GBQUserService gbqUserService) {
		this.gbqUserService = gbqUserService;
	}

	@Override
	public GBQUserDTO checkLogin(UserVO user, KeyChainEntries keyChainEntries, HttpServletRequest request,
			HttpServletResponse response) {
		GBQUserDTO userDTO = new GBQUserDTO();
		try {
			logger.info("userVo " + user.getEmailID() + " " + user.getPassword());
			UserVO dbUser = userDAO.getUserVOByEmailID(user.getEmailID());
			if (dbUser != null && StringUtils.hasText(dbUser.getPassword())) {
				byte[] encBytes = Base64.decodeBase64(dbUser.getPassword());
				byte[] encryptionKey = keyChainEntries.getAesKeyBytes();
				SecretKeySpec encKey = new SecretKeySpec(encryptionKey, AuthorizationServiceConstants.AES);
				EncryptionFactory.Encryption enc = EncryptionFactory.getInstance(encKey.getAlgorithm());
				byte[] idBytes = enc.decrypt(encKey.getEncoded(), encBytes);
				String decryptedPassword = new String(idBytes, AuthorizationServiceConstants.CHAR_SET);

				byte[] hashedPasswordDB = Base64.decodeBase64(decryptedPassword);
				Hash passwordHash = HashFactory.getInstance(AuthorizationServiceConstants.HMACSHA256);
				boolean isPasswordMatch = passwordHash.match(KEY, user.getPassword().getBytes(), hashedPasswordDB);
				logger.info("userVo " + user.isEmailVerified() + dbUser.toString());
				if (isPasswordMatch && dbUser.isEmailVerified() != null
						&& dbUser.isEmailVerified().equalsIgnoreCase(AuthorizationServiceConstants.YES)) {
					userDTO.setStatus(AuthorizationServiceConstants.SUCCESS);
					userDTO.setDestination(AuthorizationServiceConstants.SUCCESS_PAGE);
				} else if (isPasswordMatch) {
					String verifyCode = sendVerificationCodeToEmail(dbUser);
					Map<String, String> map = new HashMap<String, String>();
					map.put(AuthorizationServiceConstants.USER_ID_TYPE_EMAIL, user.getEmailID());
					map.put(AuthorizationServiceConstants.SECURE_VERIFICATION_CODE, verifyCode);
					userDTO.setStatus(AuthorizationServiceConstants.VERIFY);
					userDTO.setDestination(AuthorizationServiceConstants.VERIFY_CODE_PAGE);
					userDTO.setCookieContent(map);
				} else {
					userDTO.setStatus(AuthorizationServiceConstants.LOGIN);
					userDTO.setDestination(AuthorizationServiceConstants.LOGIN_PAGE);
				}
			} else {
				userDTO.setStatus(AuthorizationServiceConstants.LOGIN);
				userDTO.setDestination(AuthorizationServiceConstants.LOGIN_PAGE);
			}
		} catch (UnsupportedEncodingException | GBQUserException e) {
			userDTO.setStatus(AuthorizationServiceConstants.ERROR);
			userDTO.setDestination(AuthorizationServiceConstants.ERROR_PAGE);
		}
		return userDTO;
	}

	@Override
	@Transactional(propagation = Propagation.REQUIRED, rollbackFor = Throwable.class)
	public GBQUserDTO addUser(final UserVO userVO, ModelMap model, KeyChainEntries keyChainEntries,
			HttpServletRequest request, HttpServletResponse response) throws GBQUserException {
		GBQUserDTO userDTO = new GBQUserDTO();
		userVO.setUserID(UUID.randomUUID().toString());
		try {
			Hash passwordHash = HashFactory.getInstance(AuthorizationServiceConstants.HMACSHA256);
			byte[] hashedPassword = passwordHash.hash(KEY, userVO.getPassword().getBytes());
			String macString = Base64.encodeBase64URLSafeString(hashedPassword);

			// Encrypt the password
			byte[] encryptionKey = keyChainEntries.getAesKeyBytes();
			SecretKeySpec secretKey = new SecretKeySpec(encryptionKey, AuthorizationServiceConstants.AES);
			EncryptionFactory.Encryption enc = EncryptionFactory.getInstance(secretKey.getAlgorithm());
			byte[] encBytes;

			encBytes = enc.encrypt(secretKey.getEncoded(), macString.getBytes(AuthorizationServiceConstants.CHAR_SET));
			String encPasswordStringWithHash = Base64.encodeBase64URLSafeString(encBytes);
			logger.debug("addUser()::Adding user with user id:- " + userVO.getEmailID());
			userVO.setPassword(encPasswordStringWithHash);
			getUserDAO().addUser(userVO);
			logger.debug("addUser()::Sending verification code to email id:- " + userVO.getEmailID() + " of "
					+ userVO.getFirstName() + " " + userVO.getLastName());
			String verifyCode = sendVerificationCodeToEmail(userVO);
			Map<String, String> map = new HashMap<String, String>();
			map.put(AuthorizationServiceConstants.USER_ID_TYPE_EMAIL, userVO.getUserID());
			map.put(AuthorizationServiceConstants.SECURE_VERIFICATION_CODE, verifyCode);
			userDTO.setStatus(AuthorizationServiceConstants.VERIFY);
			userDTO.setDestination(AuthorizationServiceConstants.VERIFY_CODE_PAGE);
			userDTO.setCookieContent(map);
		} catch (GBQUserException | UnsupportedEncodingException e) {
			userDTO.setStatus(AuthorizationServiceConstants.ERROR);
			userDTO.setDestination(AuthorizationServiceConstants.ERROR_PAGE);
		}
		return userDTO;
	}

	@Override
	public UserVO getUser(final String userID, final String userIDType) throws GBQUserException {
		if (AuthorizationServiceConstants.USER_ID_TYPE_EMAIL.equals(userIDType)) {
			return getUserDAO().getUserVOByEmailID(userID);
		} else {
			return getUserDAO().getUserVOByPhoneNumber(userID);
		}
	}

	@Override
	@Transactional(propagation = Propagation.REQUIRED)
	public void updateUser(final UserVO userVO) throws GBQUserException {
		getUserDAO().updateUser(userVO);
	}

	@Override
	@Transactional(propagation = Propagation.REQUIRED)
	public void deleteUser(final String userID) throws GBQUserException {
		getUserDAO().deleteUser(userID);
	}

	@Override
	public UserVO getUserVOByEmailID(final String userID) throws GBQUserException {
		return getUserDAO().getUserVOByEmailID(userID);
	}

	@Override
	public UserVO getUserVOByPhoneNumber(final String userID) throws GBQUserException {
		return getUserDAO().getUserVOByPhoneNumber(userID);
	}

	@Override
	public Boolean checkUserLogon(final UserVO userVO) throws GBQUserException {
		String email = userVO.getEmailID();
		String phoneNumber = userVO.getPhoneNumber();
		UserVO userInfo = null;
		if (StringUtils.hasText(email)) {
			userInfo = getUserDAO().getUserVOByEmailID(email);
		}
		if (StringUtils.hasText(phoneNumber)) {
			userInfo = getUserDAO().getUserVOByPhoneNumber(phoneNumber);
		}
		if (null == userInfo) {
			throw new GBQUserException("User Not Found");
		}
		try {
			SecureHasher hasher = SecureHasher.getDefaultEngine();
			hasher.setSalt(userVO.getUserSalt());
			return hasher.check(userVO.getPassword(), userInfo.getPassword());
		} catch (Exception e) {
			throw new GBQUserException("Exception while comparing user hash", e);
		}
	}

	@Override
	public String sendVerificationCodeToEmail(final UserVO userVO) throws GBQUserException {
		int randomInteger = 0;
		SecureRandom random = new SecureRandom();
		randomInteger = random.nextInt(AuthorizationServiceConstants.SECURE_RANDOM_LIMIT);

		logger.debug("addUser()::Verification code to email id:- " + randomInteger);

		/*
		 * EmailService emailService = new EmailService(); MailVO mailVO = new MailVO();
		 * mailVO.setFromAddress(AuthorizationServiceConstants.FROM_EMAIL_ADDRESS);
		 * mailVO.setToAddress(AuthorizationServiceConstants.FROM_EMAIL_ADDRESS);
		 * mailVO.setSubject("Send Random number"); mailVO.setBody("Test Body" +
		 * randomInteger); emailService.sendEmail(mailVO);
		 */
		return String.valueOf(randomInteger);
	}

	@Override
	public String verifyUser(String email, String verifyCode, ModelMap model, HttpServletRequest httpRequest,
			HttpServletResponse httpResponse) throws GBQUserException {
		Map<String, String> cookieContent = cookieManager.getExistingCookie(httpRequest, httpResponse, COOKIE_NAME);
		String verifyCodeFromModel = cookieContent.get(AuthorizationServiceConstants.SECURE_VERIFICATION_CODE);
		String emailFromCookie = cookieContent.get(AuthorizationServiceConstants.USER_ID_TYPE_EMAIL);
		String response = AuthorizationServiceConstants.LOGIN_PAGE;
		logger.debug("verifyUser()::verifyCode:- " + verifyCode + " verifyCodeFromModel:- " + verifyCodeFromModel + "email " + emailFromCookie);
		if (StringUtils.hasText(verifyCode) && StringUtils.hasText(verifyCodeFromModel)
				&& verifyCode.equals(verifyCodeFromModel)) {
			boolean isEmailVerifiedUpdated = userDAO.updateUserEmailVerificationStatus(emailFromCookie,
					AuthorizationServiceConstants.YES);
			logger.debug("verifyUser()::User ID is verified.");
			if (isEmailVerifiedUpdated) {
				response = AuthorizationServiceConstants.LOGIN_PAGE;
			}else {
				response = AuthorizationServiceConstants.VERIFY_CODE_PAGE;
			}
		} else if (StringUtils.hasText(verifyCode) && StringUtils.hasText(verifyCodeFromModel)
				&& !verifyCode.equals(verifyCodeFromModel)) {
			response = AuthorizationServiceConstants.VERIFY_CODE_PAGE;
		} else if (!StringUtils.hasText(verifyCode) || !StringUtils.hasText(verifyCodeFromModel)) {
			throw new GBQUserException("System Exception has occurred. Please try again!");
		}
		return response;
	}
}
