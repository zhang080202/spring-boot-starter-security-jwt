package com.github.security.utils;

import java.util.Collection;
import java.util.Date;
import java.util.HashMap;
import java.util.List;
import java.util.stream.Collectors;

import org.apache.commons.lang3.StringUtils;
import org.springframework.security.core.GrantedAuthority;

import io.jsonwebtoken.Claims;
import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.SignatureAlgorithm;

/**
 * jwt 工具类
 *
 */
public class JwtUtils {
	public static final String	TOKEN_HEADER		= "Authorization";
	public static final String	TOKEN_PREFIX		= "Bearer ";

	private static final String	SECRET				= "jwtsecretdemo";
	private static final String	ISS					= "echisan";
	private static final String	ROLE_CLAIMS			= "rol";

	// 过期时间是3600秒，既是1个小时
	private static final long	EXPIRATION			= 3600L;

	// 选择了记住我之后的过期时间为7天
	private static final long	EXPIRATION_REMEMBER	= 604800L;

	// 创建token
	public static String createToken(String username, Collection<? extends GrantedAuthority> authorities, boolean isRememberMe) {
		List<String> roles = authorities.stream()
										.map((auth) -> auth.getAuthority())
										.collect(Collectors.toList());
		long expiration = isRememberMe ? EXPIRATION_REMEMBER : EXPIRATION;
		HashMap<String, Object> map = new HashMap<>();
		map.put(ROLE_CLAIMS, StringUtils.join(roles, ","));
		return Jwts.builder()
				   .signWith(SignatureAlgorithm.HS512, SECRET)
				   .setClaims(map)
				   .setIssuer(ISS)
				   .setSubject(username)
				   .setIssuedAt(new Date())
				   .setExpiration(new Date(System.currentTimeMillis() + expiration * 1000))
				   .compact();
	}

	// 从token中获取用户名
	public static String getUsername(String token) {
		return getTokenBody(token).getSubject();
	}
	
	// 获取用户角色
    public static String getUserRole(String token){
        return (String) getTokenBody(token).get(ROLE_CLAIMS);
    }

	// 是否已过期
	public static boolean isExpiration(String token) {
		return getTokenBody(token).getExpiration().before(new Date());
	}

	private static Claims getTokenBody(String token) {
		return Jwts.parser().setSigningKey(SECRET).parseClaimsJws(token).getBody();
	}
}
