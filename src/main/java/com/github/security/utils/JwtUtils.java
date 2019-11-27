package com.github.security.utils;

import java.security.Key;
import java.util.Collection;
import java.util.Date;
import java.util.HashMap;
import java.util.List;
import java.util.stream.Collectors;

import javax.crypto.SecretKey;
import javax.crypto.spec.SecretKeySpec;

import org.apache.commons.codec.binary.Base64;
import org.apache.commons.lang3.StringUtils;
import org.springframework.security.authentication.BadCredentialsException;
import org.springframework.security.core.GrantedAuthority;

import io.jsonwebtoken.Claims;
import io.jsonwebtoken.Jws;
import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.SignatureAlgorithm;

/**
 * jwt 工具类
 *
 */
public class JwtUtils {
	public static final String	TOKEN_HEADER		= "Authorization";
	public static final String	TOKEN_PREFIX		= "Bearer ";
	public static final String  TOKEN_SALT          = "jwtStarter";

	private static final String	ISS					= "echisan";
	private static final String	ROLE_CLAIMS			= "rol";
	
	private static final SignatureAlgorithm JWT_ALG = SignatureAlgorithm.HS256;
	// 过期时间是3600秒，既是1个小时
	private static final long	EXPIRATION			= 3600L;

	// 选择了记住我之后的过期时间为7天
	private static final long	EXPIRATION_REMEMBER	= 604800L;

	// 创建token
	public static String createToken(String username, Collection<? extends GrantedAuthority> authorities, boolean isRememberMe, String salt) {
		List<String> roles = authorities.stream()
										.map((auth) -> auth.getAuthority())
										.collect(Collectors.toList());
		long expiration = isRememberMe ? EXPIRATION_REMEMBER : EXPIRATION;
		HashMap<String, Object> map = new HashMap<>();
		map.put(ROLE_CLAIMS, StringUtils.join(roles, ","));
		return Jwts.builder()
				   .signWith(JWT_ALG, salt)
				   .setClaims(map)
				   .setIssuer(ISS)
				   .setSubject(username)
				   .setIssuedAt(new Date())
				   .setExpiration(new Date(System.currentTimeMillis() + expiration * 1000))
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
		return Jwts.parser().setSigningKey(salt).parseClaimsJws(token).getBody();
	}
	
	/**
     * 解析JWT
     *
     * @param key       jwt 加密密钥
     * @param claimsJws jwt 内容文本
     * @return {@link Jws}
     * @throws Exception
     */
    public static Jws<Claims> parseJWT(Key key, String token) {
        return Jwts.parser()
        		   .setSigningKey(key)
        		   .parseClaimsJws(token);
    }

    /**
     * 使用指定密钥生成规则，生成JWT加解密密钥
     *
     * @param alg  加解密类型
     * @param rule 密钥生成规则
     * @return
     */
    public static SecretKey generateKey(String salt) {
        // 将密钥生成键转换为字节数组
        byte[] bytes = Base64.decodeBase64(salt);
        // 根据指定的加密方式，生成密钥
        return new SecretKeySpec(bytes, JWT_ALG.getJcaName());
    }
    
    /**
     * 校验JWT
     *
     * @param claimsJws jwt 内容文本
     * @return ture or false
     */
    public static void checkJWT(String token, String salt, String username) {
        SecretKey key = generateKey(salt);
        // 获取 JWT 的 payload 部分
        Claims claims = parseJWT(key, token).getBody();
        if (!username.equals(claims.getSubject())) {
			throw new BadCredentialsException(" Jwt Verify fail");
		}
    }

}
