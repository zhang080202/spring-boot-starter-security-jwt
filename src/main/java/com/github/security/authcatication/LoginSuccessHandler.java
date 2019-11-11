package com.github.security.authcatication;

import java.io.IOException;

import javax.servlet.ServletException;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

import org.apache.commons.lang3.StringUtils;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.web.authentication.AuthenticationSuccessHandler;

import com.github.security.service.JwtUserDetailsService;
import com.github.security.utils.JwtUtils;

/**
 * 登录成功返回token
 * @author zhangyf
 * 2019年8月17日
 */
public class LoginSuccessHandler implements AuthenticationSuccessHandler{
	
	private JwtUserDetailsService jwtUserDetailsService;
	
	private Logger logger = LoggerFactory.getLogger(LoginSuccessHandler.class);
	
	public LoginSuccessHandler(JwtUserDetailsService jwtUserDetailsService) {
		this.jwtUserDetailsService = jwtUserDetailsService;
	}

	@Override
	public void onAuthenticationSuccess(HttpServletRequest request, HttpServletResponse response,
			Authentication authentication) throws IOException, ServletException {
		UserDetails user = (UserDetails)authentication.getPrincipal();
        String token = generToken((UserDetails)authentication.getPrincipal(), getSalt(user.getUsername()));
        
		jwtUserDetailsService.insertSalt(token, user);
		response.setHeader("Authorization", JwtUtils.TOKEN_PREFIX + token);
		
		logger.info("Login success! token : " + token);
	}
	
	private String generToken(UserDetails user, String salt) {
		return JwtUtils.createToken(user.getUsername(), user.getAuthorities(), false, salt);
	}
	
	private String getSalt(String username) {
		String salt = jwtUserDetailsService.getSalt(username);
		if (StringUtils.isBlank(salt)) {
			salt = JwtUtils.TOKEN_SALT;
		}
		return salt;
	}
}
