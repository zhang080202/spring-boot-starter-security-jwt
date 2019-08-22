package com.github.security.service;

import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;

/**
 * 实现 loadUserByUsername 方法
 * 根据项目需求是否需要产生随机salt 保存至数据库或缓存中
 * @author Fly
 *
 */
public abstract class JwtUserDetailsService implements UserDetailsService {
	
	public void insertSalt(String salt, UserDetails user) {
		// null implements
	}
	
	public void removeSalt(String username) {
		// null implements
	}
	
	/**
	 * BCrypt.gensalt()
	 * 正式开放可使用该方法生成随机盐
	 * @param username
	 * @return
	 */
	public String getSalt(String username) {
		// always return null
		return null;
	}

}
