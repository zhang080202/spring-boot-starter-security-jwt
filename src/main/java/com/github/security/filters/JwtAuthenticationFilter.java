package com.github.security.filters;

import java.io.IOException;
import java.util.ArrayList;
import java.util.List;

import javax.servlet.FilterChain;
import javax.servlet.ServletException;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

import org.apache.commons.lang3.StringUtils;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.InsufficientAuthenticationException;
import org.springframework.security.authentication.InternalAuthenticationServiceException;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.web.authentication.AuthenticationFailureHandler;
import org.springframework.security.web.authentication.AuthenticationSuccessHandler;
import org.springframework.security.web.authentication.NullRememberMeServices;
import org.springframework.security.web.authentication.RememberMeServices;
import org.springframework.security.web.authentication.SavedRequestAwareAuthenticationSuccessHandler;
import org.springframework.security.web.authentication.SimpleUrlAuthenticationFailureHandler;
import org.springframework.security.web.util.matcher.AntPathRequestMatcher;
import org.springframework.security.web.util.matcher.RequestHeaderRequestMatcher;
import org.springframework.security.web.util.matcher.RequestMatcher;
import org.springframework.util.AntPathMatcher;
import org.springframework.util.Assert;
import org.springframework.util.PathMatcher;
import org.springframework.web.filter.OncePerRequestFilter;

import com.auth0.jwt.JWT;
import com.auth0.jwt.exceptions.JWTDecodeException;
import com.github.security.utils.JwtAuthenticationToken;

/**
 * jwt认证过滤器
 * 
 * @author zhangyf
 * @date 2019年8月16日
 */
public class JwtAuthenticationFilter extends OncePerRequestFilter {

	private RequestMatcher requiresAuthenticationRequestMatcher;
	private List<RequestMatcher> permissiveRequestMatchers;
	private AuthenticationManager authenticationManager;

	private AuthenticationSuccessHandler successHandler = new SavedRequestAwareAuthenticationSuccessHandler();
	private AuthenticationFailureHandler failureHandler = new SimpleUrlAuthenticationFailureHandler();

	private RememberMeServices rememberMeServices = new NullRememberMeServices();

	private static final String AUTHORIZATION_HEADER = "Authorization";
	private static final String AUTHORIZATION_START_STRING = "Bearer ";

	public JwtAuthenticationFilter() {
		this.requiresAuthenticationRequestMatcher = new RequestHeaderRequestMatcher(AUTHORIZATION_HEADER);
	}

	@Override
	public void afterPropertiesSet() {
		Assert.notNull(authenticationManager, "authenticationManager must be specified");
		Assert.notNull(successHandler, "AuthenticationSuccessHandler must be specified");
		Assert.notNull(failureHandler, "AuthenticationFailureHandler must be specified");
	}

	protected String getJwtToken(HttpServletRequest request) {
		String authInfo = request.getHeader(AUTHORIZATION_HEADER);
		return StringUtils.removeStart(authInfo, AUTHORIZATION_START_STRING);
	}

	@Override
	protected void doFilterInternal(HttpServletRequest request, HttpServletResponse response, FilterChain filterChain)
			throws ServletException, IOException {
		// 验证是否是白名单
		if (permissiveRequest(request)) {
			filterChain.doFilter(request, response);
			return;
		}
		Authentication authResult = null;
		AuthenticationException failed = null;
		try {
			// 提取token 并委托给JwtAuthenticationProvider进行认证
			String token = getJwtToken(request);
			if (StringUtils.isNotBlank(token)) {
				JwtAuthenticationToken authToken = new JwtAuthenticationToken(JWT.decode(token));
				authResult = this.getAuthenticationManager().authenticate(authToken);
			} else {
				failed = new InsufficientAuthenticationException("JWT is Empty");
			}
		} catch (JWTDecodeException e) {
			logger.error("JWT format error", e);
			failed = new InsufficientAuthenticationException("JWT format error", failed);
		} catch (InternalAuthenticationServiceException e) {
			logger.error("An internal error occurred while trying to authenticate the user.", failed);
			failed = e;
		} catch (AuthenticationException e) {
			failed = e;
		}
		if (authResult != null) {
			successfulAuthentication(request, response, filterChain, authResult);
		} else if (!permissiveRequest(request)) {
			unsuccessfulAuthentication(request, response, failed);
			return;
		}

		filterChain.doFilter(request, response);
	}

	protected void unsuccessfulAuthentication(HttpServletRequest request, HttpServletResponse response,
			AuthenticationException failed) throws IOException, ServletException {
		SecurityContextHolder.clearContext();

		rememberMeServices.loginFail(request, response);
		failureHandler.onAuthenticationFailure(request, response, failed);
	}

	protected void successfulAuthentication(HttpServletRequest request, HttpServletResponse response, FilterChain chain,
			Authentication authResult) throws IOException, ServletException {
		SecurityContextHolder.getContext().setAuthentication(authResult);

		rememberMeServices.loginSuccess(request, response, authResult);
		successHandler.onAuthenticationSuccess(request, response, authResult);
	}

	protected AuthenticationManager getAuthenticationManager() {
		return authenticationManager;
	}

	public void setAuthenticationManager(AuthenticationManager authenticationManager) {
		this.authenticationManager = authenticationManager;
	}

	protected boolean requiresAuthentication(HttpServletRequest request, HttpServletResponse response) {
		return requiresAuthenticationRequestMatcher.matches(request);
	}

	protected boolean permissiveRequest(HttpServletRequest request) {
		if (permissiveRequestMatchers == null)
			return false;
		for (RequestMatcher permissiveMatcher : permissiveRequestMatchers) {
			if (permissiveMatcher.matches(request))
				return true;
		}
		return false;
	}

	public void setPermissiveUrl(String... urls) {
		if (permissiveRequestMatchers == null)
			permissiveRequestMatchers = new ArrayList<>();
		for (String url : urls)
			permissiveRequestMatchers.add(new AntPathRequestMatcher(url));
	}

	public void setAuthenticationSuccessHandler(AuthenticationSuccessHandler successHandler) {
		Assert.notNull(successHandler, "successHandler cannot be null");
		this.successHandler = successHandler;
	}

	public void setAuthenticationFailureHandler(AuthenticationFailureHandler failureHandler) {
		Assert.notNull(failureHandler, "failureHandler cannot be null");
		this.failureHandler = failureHandler;
	}
	
	protected AuthenticationSuccessHandler getSuccessHandler() {
		return successHandler;
	}

	protected AuthenticationFailureHandler getFailureHandler() {
		return failureHandler;
	}

	public RememberMeServices getRememberMeServices() {
		return rememberMeServices;
	}

	public void setRememberMeServices(RememberMeServices rememberMeServices) {
		this.rememberMeServices = rememberMeServices;
	}

}
