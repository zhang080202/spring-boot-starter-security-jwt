package com.github.security.authcatication;

import java.util.Calendar;

import org.springframework.security.authentication.AuthenticationProvider;
import org.springframework.security.authentication.BadCredentialsException;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.core.userdetails.UserCache;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.core.userdetails.cache.NullUserCache;
import org.springframework.util.Assert;

import com.auth0.jwt.JWT;
import com.auth0.jwt.JWTVerifier;
import com.auth0.jwt.algorithms.Algorithm;
import com.auth0.jwt.interfaces.DecodedJWT;
import com.github.security.utils.JwtAuthenticationToken;

/**
 * jwt认证主要逻辑
 * @author zhangyf
 * @date 2019年8月16日
 */
public class JwtAuthenticationProvider implements AuthenticationProvider {
	
	private UserDetailsService userDetailsService;
	
	private UserCache userCache = new NullUserCache();
	
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
		// 验证 token
		String encryptSalt = user.getPassword();
		try {
            Algorithm algorithm = Algorithm.HMAC256(encryptSalt);
            JWTVerifier verifier = JWT.require(algorithm)
				                      .withSubject(username)
				                      .build();
            verifier.verify(jwt.getToken());
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

	public void setUserDetailsService(UserDetailsService userDetailsService) {
		this.userDetailsService = userDetailsService;
	}

	public void setUserCache(UserCache userCache) {
		this.userCache = userCache;
	}
	
}
