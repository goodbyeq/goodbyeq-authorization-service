package com.goodbyeq.user.dao.impl;

import javax.persistence.EntityManager;
import javax.persistence.EntityManagerFactory;
import javax.persistence.EntityTransaction;
import javax.persistence.PersistenceContext;
import javax.transaction.Transactional;

import org.hibernate.SessionFactory;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.orm.hibernate5.support.HibernateDaoSupport;
import org.springframework.stereotype.Repository;

import com.goodbyeq.exception.GBQUserException;
import com.goodbyeq.user.dao.api.UserDAO;
import com.goodbyeq.user.db.bo.UserVO;

@Repository("userDAO")
public class UserDAOImpl extends HibernateDaoSupport implements UserDAO {
	private static final Logger logger = LoggerFactory.getLogger(UserDAOImpl.class);

	@PersistenceContext
	private EntityManager entityManager;

	public EntityManager getEntityManager() {
		return entityManager;
	}

	public void setEntityManager(EntityManager entityManager) {
		this.entityManager = entityManager;
	}

	@Autowired
	public void anyMethodName(SessionFactory sessionFactory) {
		setSessionFactory(sessionFactory);
	}

	@Override
	public void addUser(final UserVO userVO) throws GBQUserException {
		//userVO.setUserSysGUID(UUID.randomUUID().toString());
		try {
			getEntityManager().persist(userVO);		
		}catch(Exception exception) {
			logger.debug("userDAO::addUser()::userVO:- " + userVO);
			throw new GBQUserException("Error while creating UserVO " + exception.getMessage());
		}
	}

	@Override
	public void updateUser(final UserVO userVO) throws GBQUserException {
		getEntityManager().merge(userVO);
	}

	@Override
	public void deleteUser(final String userID) throws GBQUserException {
		UserVO userVO = getEntityManager().find(UserVO.class, userID);
		getEntityManager().remove(userVO);
	}

	@Override
	public UserVO getUserVOByEmailID(final String emailID) throws GBQUserException {
		UserVO userVO = null;
		try {
			userVO = (UserVO) entityManager.createQuery("SELECT u FROM UserVO u WHERE u.emailID=:email")
					.setParameter("email", emailID).getSingleResult();
		} catch (final Exception e) {
			logger.error("Exception in getUserVOByEmailID", e);
			throw new GBQUserException(e);
		}
		return userVO;
	}

	@Override
	public UserVO getUserVOByPhoneNumber(final String phoneNumber) throws GBQUserException {
		UserVO userVO = null;
		try {
			userVO = (UserVO) entityManager.createQuery("SELECT u FROM UserVO u WHERE u.phoneNumber=:phone")
					.setParameter("phone", phoneNumber).getSingleResult();
		} catch (final Exception e) {
			logger.error("Exception in getUserVOByPhoneNumber", e);
			throw new GBQUserException(e);
		}
		return userVO;
	}
	
	@Override
	@Transactional
	public boolean updateUserEmailVerificationStatus(String email, String verificationStatus) throws GBQUserException {	
		try {
			/*UserVO userVO = (UserVO) entityManager.createQuery("SELECT u FROM UserVO u WHERE u.emailID=:email")
					.setParameter("email", email).getSingleResult();
			userVO.setIsEmailVerified(AuthorizationServiceConstants.YES);
			EntityManager em = emf.createEntityManager();
			EntityTransaction entityTransaction = em.getTransaction();
			entityTransaction.begin();*/
			int isUpdated = entityManager.createNativeQuery("UPDATE GBQ_USER u SET u.ISEMAILVERFIED=:emailVerified WHERE u.EMAIL=:email")
					.setParameter("emailVerified", verificationStatus).setParameter("email", email).executeUpdate();
			if(isUpdated > 0) {
				return true;
			}
			//entityTransaction.commit();
		} catch (final Exception e) {
			logger.error("Exception in getUserVOByPhoneNumber", e);
			throw new GBQUserException(e);
		}
		return false;
	}


}
