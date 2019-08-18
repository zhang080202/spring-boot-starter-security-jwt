package com.github.security.service;

import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;

/**
 * 实现 该接口需 实现insertToken 和 loadUserByUsername 方法
 * @author Fly
 *
 */
public interface JwtUserDetailsService extends UserDetailsService {
	
	public void insertSalt(String salt, UserDetails user);
	
	public void removeSalt(String username);
	
	public String getSalt(String username);

}
