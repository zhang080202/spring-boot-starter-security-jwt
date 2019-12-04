package com.github.security.utils;

import java.util.Collection;
import java.util.Date;
import java.util.HashMap;
import java.util.List;
import java.util.stream.Collectors;

import org.apache.commons.lang3.StringUtils;
import org.springframework.security.authentication.BadCredentialsException;
import org.springframework.security.core.GrantedAuthority;

import io.jsonwebtoken.Claims;
import io.jsonwebtoken.Jws;
import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.SignatureAlgorithm;
import io.jsonwebtoken.security.Keys;

/**
 * jwt 工具类
 *
 */
public class JwtUtils {
	//default secret String
	public static final String  TOKEN_SECRET          = "NsTheJM9ckeYl1cNpW5TQMqxfapDcJDrcSlRBlLNBKw=";

	private static final String	ROLE_CLAIMS			= "rol";
	
	private static final SignatureAlgorithm JWT_ALG = SignatureAlgorithm.HS256;
	// 过期时间2个小时
	private static final long	EXPIRATION			= 7200L;

	// 创建token
	public static String createToken(String username, Collection<? extends GrantedAuthority> authorities, String salt) {
		List<String> roles = authorities.stream()
										.map((auth) -> auth.getAuthority())
										.collect(Collectors.toList());
		
		HashMap<String, Object> map = new HashMap<>();
		map.put(ROLE_CLAIMS, StringUtils.join(roles, ","));
		return Jwts.builder()
				   .signWith(Keys.hmacShaKeyFor(salt.getBytes()), JWT_ALG)
				   .setClaims(map)
				   .setSubject(username)
				   .setIssuedAt(new Date())
				   .setExpiration(new Date(System.currentTimeMillis() + EXPIRATION * 1000))
				   .compact();
	}

	// 从token中获取用户名
	public static String getUsername(String token, String salt) {
		return getTokenBody(token, salt).getSubject();
	}
	
	// 获取用户角色
    public static String getUserRole(String token, String salt){
        return (String) getTokenBody(token, salt).get(ROLE_CLAIMS);
    }

	// 是否已过期
	public static boolean isExpiration(String token, String salt) {
		return getTokenBody(token, salt).getExpiration().before(new Date());
	}

	private static Claims getTokenBody(String token, String salt) {
		return Jwts.parser()
				   .setSigningKey(salt)
				   .parseClaimsJws(token)
				   .getBody();
	}
	
	/**
     * 解析JWT
     *
     * @param key       jwt 加密密钥
     * @param claimsJws jwt 内容文本
     * @return {@link Jws}
     * @throws Exception
     */
    public static Jws<Claims> parseJWT(String salt, String token) {
        return Jwts.parser()
        		   .setSigningKey(salt.getBytes())
        		   .parseClaimsJws(token);
    }

    /**
     * 校验JWT
     *
     * @param claimsJws jwt 内容文本
     * @return ture or false
     */
    public static void checkJWT(String token, String salt, String username) {
        // 获取 JWT 的 payload 部分
        Claims claims = parseJWT(salt, token).getBody();
        if (!username.equals(claims.getSubject())) {
			throw new BadCredentialsException(JwtConstant.TOKEN_VERIFY_ERROR);
		}
    }

}
