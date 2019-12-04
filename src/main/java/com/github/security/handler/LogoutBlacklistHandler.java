package com.github.security.handler;

import java.util.Calendar;
import java.util.Date;

import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

import org.apache.commons.lang3.StringUtils;
import org.springframework.security.authentication.BadCredentialsException;
import org.springframework.security.core.Authentication;
import org.springframework.security.web.authentication.logout.LogoutHandler;

import com.auth0.jwt.JWT;
import com.auth0.jwt.interfaces.DecodedJWT;
import com.github.security.utils.CacheManager;
import com.github.security.utils.JwtConstant;

/**
 * 注销登录 将token 加入黑名单
 * @author zhangyf
 */
public class LogoutBlacklistHandler implements LogoutHandler {

	@Override
	public void logout(HttpServletRequest request, HttpServletResponse response, Authentication authentication) {
		DecodedJWT jwt = getJwtToken(request);
		
		CacheManager.setData(jwt.getToken(), jwt, extractExpireTime(jwt));
	}

	private int extractExpireTime(DecodedJWT jwt) {
		int expire = 0;
		Date expiresAt = jwt.getExpiresAt();
		if (!expiresAt.before(Calendar.getInstance().getTime())) {
			expire = (int) (expiresAt.getTime() - System.currentTimeMillis());
		} 
		return expire;
	}
	
	private DecodedJWT getJwtToken(HttpServletRequest request) {
		String authInfo = request.getHeader(JwtConstant.AUTHORIZATION_HEADER);
		if (StringUtils.isBlank(authInfo)) {
			throw new BadCredentialsException(JwtConstant.TOKEN_NOT_EMPTY);
		}
		return JWT.decode(StringUtils.removeStart(authInfo, JwtConstant.AUTHORIZATION_START_STRING));
	}

}
