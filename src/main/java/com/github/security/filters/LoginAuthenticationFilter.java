package com.github.security.filters;

import java.io.IOException;
import java.nio.charset.Charset;

import javax.servlet.ServletException;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.web.authentication.AbstractAuthenticationProcessingFilter;
import org.springframework.security.web.util.matcher.AntPathRequestMatcher;
import org.springframework.util.Assert;
import org.springframework.util.StreamUtils;
import org.springframework.util.StringUtils;

import com.alibaba.fastjson.JSON;
import com.alibaba.fastjson.JSONObject;
import com.github.security.service.JwtUserDetailsService;

/**
 *  登录过滤器
 * @author zhangyf
 * 2019年8月17日
 */
public class LoginAuthenticationFilter extends AbstractAuthenticationProcessingFilter {
	
	public static final String SPRING_SECURITY_FORM_USERNAME_KEY = "username";
	public static final String SPRING_SECURITY_FORM_PASSWORD_KEY = "password";

	private String usernameParameter = SPRING_SECURITY_FORM_USERNAME_KEY;
	private String passwordParameter = SPRING_SECURITY_FORM_PASSWORD_KEY;
	
	private JwtUserDetailsService jwtUserDetailsService;
	
	public LoginAuthenticationFilter() {
		super(new AntPathRequestMatcher("/**/login", "POST"));
	}
	
	@Override
	public void afterPropertiesSet() {
		Assert.notNull(getAuthenticationManager(), "authenticationManager must be specified");
		Assert.notNull(getSuccessHandler(), "AuthenticationSuccessHandler must be specified");
		Assert.notNull(getFailureHandler(), "AuthenticationFailureHandler must be specified");
	}

	@Override
	public Authentication attemptAuthentication(HttpServletRequest request, HttpServletResponse response)
			throws AuthenticationException, IOException, ServletException {
		String body = StreamUtils.copyToString(request.getInputStream(), Charset.forName("UTF-8"));
		
		String username = obtainUsername(body);
		String password = obtainPassword(body);
		
		if (username == null) 
			username = "";
		if (password == null)
			password = "";
		username = username.trim();

		UsernamePasswordAuthenticationToken authRequest = new UsernamePasswordAuthenticationToken(
				username, password);
		
		return this.getAuthenticationManager().authenticate(authRequest);
	}

	protected String obtainPassword(String body) throws IOException {
		return getStringFromRequest(body, passwordParameter);
	}

	protected String obtainUsername(String body) throws IOException {
		return getStringFromRequest(body, usernameParameter);
	}
	
	protected String getStringFromRequest(String body, String key) throws IOException {
		String result = null;
		if(StringUtils.hasText(body) && !StringUtils.isEmpty(key)) {
		    JSONObject jsonObj = JSON.parseObject(body);
		    result = jsonObj.getString(key);
		}
		return result;
	}

	public JwtUserDetailsService getJwtUserDetailsService() {
		return jwtUserDetailsService;
	}

	public void setJwtUserDetailsService(JwtUserDetailsService jwtUserDetailsService) {
		this.jwtUserDetailsService = jwtUserDetailsService;
	}
	
	
}
