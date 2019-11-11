package com.github.security.authcatication;

import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

import org.springframework.security.core.Authentication;
import org.springframework.security.core.userdetails.UserCache;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.cache.NullUserCache;
import org.springframework.security.web.authentication.logout.LogoutHandler;

import com.github.security.service.JwtUserDetailsService;

public class TokenClearLogoutHandler implements LogoutHandler {

	private JwtUserDetailsService jwtUserDetailsService;
	
	private UserCache userCache = new NullUserCache();

	public TokenClearLogoutHandler(JwtUserDetailsService jwtUserDetailsService) {
		this.jwtUserDetailsService = jwtUserDetailsService;
	}

	@Override
	public void logout(HttpServletRequest request, HttpServletResponse response, Authentication authentication) {
		clearToken(authentication);
	}

	protected void clearToken(Authentication authentication) {
		if (authentication == null)
			return;
		UserDetails user = (UserDetails) authentication.getPrincipal();
		
		userCache.removeUserFromCache(user.getUsername());
		
		if (user != null && user.getUsername() != null)
			jwtUserDetailsService.removeSalt(user.getUsername());
		
	}
	
	public void setUserCache(UserCache userCache) {
		this.userCache = userCache;
	}

}
