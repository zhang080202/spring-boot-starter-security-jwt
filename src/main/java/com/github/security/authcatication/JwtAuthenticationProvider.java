package com.github.security.authcatication;

import java.util.Calendar;

import org.apache.commons.lang3.StringUtils;
import org.springframework.beans.factory.InitializingBean;
import org.springframework.security.authentication.AuthenticationProvider;
import org.springframework.security.authentication.BadCredentialsException;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.core.userdetails.UserCache;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.cache.NullUserCache;
import org.springframework.util.Assert;

import com.auth0.jwt.interfaces.DecodedJWT;
import com.github.security.service.JwtUserDetailsService;
import com.github.security.utils.JwtAuthenticationToken;
import com.github.security.utils.JwtUtils;

/**
 * jwt认证主要逻辑
 * @author zhangyf
 * @date 2019年8月16日
 */
public class JwtAuthenticationProvider implements AuthenticationProvider, InitializingBean {
	
	private JwtUserDetailsService userDetailsService;
	
	private UserCache userCache = new NullUserCache();
	

	@Override
	public void afterPropertiesSet() throws Exception {
		Assert.notNull(this.userCache, "A user cache must be set");
		Assert.notNull(this.userDetailsService, "A UserDetailsService must be set");
	}
	
	@Override
	public Authentication authenticate(Authentication authentication) throws AuthenticationException {
		DecodedJWT jwt = ((JwtAuthenticationToken) authentication).getToken();
		Assert.notNull(jwt, "Jwt token is null");
		//验证token是否过期
		if(jwt.getExpiresAt().before(Calendar.getInstance().getTime()))
			return null;
		
		//从缓存或数据库中获取user对象
		String username = jwt.getSubject();
		UserDetails user = userCache.getUserFromCache(username);
		
		if (user == null) {
			user = userDetailsService.loadUserByUsername(username);
			if (user == null) {
				return null;
			}
		}
		String salt = getSalt(username);
		try {
			JwtUtils.checkJWT(jwt.getToken(), salt, username);
        } catch (Exception e) {
            throw new BadCredentialsException("Jwt verify fail", e);
        }
		
		JwtAuthenticationToken token = new JwtAuthenticationToken(user, jwt, user.getAuthorities());
		return token;
	}

	@Override
	public boolean supports(Class<?> authentication) {
		return authentication.isAssignableFrom(JwtAuthenticationToken.class);
	}

	public void setUserDetailsService(JwtUserDetailsService userDetailsService) {
		this.userDetailsService = userDetailsService;
	}

	public void setUserCache(UserCache userCache) {
		this.userCache = userCache;
	}
	
	protected String getSalt(String username) {
		String salt = userDetailsService.getSalt(username);
		if (StringUtils.isBlank(salt)) {
			salt = JwtUtils.TOKEN_SALT;
		}
		return salt;
	}
	
}
