package com.github.security.authcatication;

import java.io.IOException;
import java.time.LocalDateTime;
import java.time.ZoneId;
import java.util.Date;

import javax.servlet.ServletException;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

import org.apache.commons.lang3.StringUtils;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.core.userdetails.UserCache;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.cache.NullUserCache;
import org.springframework.security.web.authentication.AuthenticationSuccessHandler;

import com.auth0.jwt.interfaces.DecodedJWT;
import com.github.security.service.JwtUserDetailsService;
import com.github.security.utils.JwtAuthenticationToken;
import com.github.security.utils.JwtUtils;

/**
 * 验证token成功后判断是否需要刷新token
 * @author zhangyf
 * @date 2019年8月16日
 */
public class JwtRefreshSuccessHandler implements AuthenticationSuccessHandler{
	
	private int tokenRefreshInterval; //如果不配置则默认不开启token刷新功能
	
	private JwtUserDetailsService jwtUserDetailsService;
	
	private UserCache userCache = new NullUserCache();
	
	public JwtRefreshSuccessHandler(JwtUserDetailsService jwtUserService) {
		this.jwtUserDetailsService = jwtUserService;
	}

	@Override
	public void onAuthenticationSuccess(HttpServletRequest request, HttpServletResponse response,
			Authentication authentication) throws IOException, ServletException {
		DecodedJWT jwt = ((JwtAuthenticationToken)authentication).getToken();
		boolean shouldRefresh = shouldTokenRefresh(jwt.getIssuedAt());
		//根据用户配置判断token是否过期
		if(shouldRefresh) {
			//刷新token
			//这里根据配置会刷新 Cache、DB中的token
			UserDetails user = (UserDetails)authentication.getPrincipal();
            
            userCache.putUserInCache(user);
            
            String salt = jwtUserDetailsService.getSalt(user.getUsername());
            if (StringUtils.isBlank(salt)) {
				salt = JwtUtils.TOKEN_SALT;
			}
            String newToken = generToken(user, salt);
            jwtUserDetailsService.insertSalt(newToken, user);
            
            response.setHeader("Authorization", newToken);
        }	
	}
	
	protected boolean shouldTokenRefresh(Date issueAt){
		if (tokenRefreshInterval == 0 ) return false;
		
        LocalDateTime issueTime = LocalDateTime.ofInstant(issueAt.toInstant(), ZoneId.systemDefault());
        return LocalDateTime.now().minusSeconds(tokenRefreshInterval).isAfter(issueTime);
    }
	
	private String generToken(UserDetails user, String salt) {
		return JwtUtils.createToken(user.getUsername(), user.getAuthorities(), false, salt);
	}

	public void setUserCache(UserCache userCache) {
		this.userCache = userCache;
	}

	public void setTokenRefreshInterval(int tokenRefreshInterval) {
		this.tokenRefreshInterval = tokenRefreshInterval;
	}
	
}
