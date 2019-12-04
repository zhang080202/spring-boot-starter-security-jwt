package com.github.security.configuration;

import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.config.annotation.web.HttpSecurityBuilder;
import org.springframework.security.config.annotation.web.configurers.AbstractHttpConfigurer;
import org.springframework.security.web.authentication.AuthenticationSuccessHandler;
import org.springframework.security.web.authentication.logout.LogoutFilter;

import com.github.security.filters.JwtAuthenticationFilter;
import com.github.security.handler.JwtAuthenticationFailureHandler;

/**
 * Jwt 认证 配置器
 * @author zhangyf
 * @date 2019年8月16日
 */
public class JwtAuthenticationConfigurer<T extends JwtAuthenticationConfigurer<T, B>, B extends HttpSecurityBuilder<B>> extends AbstractHttpConfigurer<T, B> {
	
	private JwtAuthenticationFilter authFilter;
	
	public JwtAuthenticationConfigurer() {
		authFilter = new JwtAuthenticationFilter();
	}
	
	@Override
	public void configure(B builder) throws Exception {
		authFilter.setAuthenticationManager(builder.getSharedObject(AuthenticationManager.class));
		
		authFilter = postProcess(authFilter);
		builder.addFilterAfter(authFilter, LogoutFilter.class);
	}
	
	/**
	 * 设置白名单
	 * @param urls
	 * @return
	 */
	public JwtAuthenticationConfigurer<T, B> permissiveRequestUrls(String ... urls){
		authFilter.setPermissiveUrl(urls);
		return this;
	}
	
	/**
	 * 设置认证成功后的操作
	 * @param successHandler
	 * @return
	 */
	public JwtAuthenticationConfigurer<T, B> authenticationSuccessHandler(AuthenticationSuccessHandler successHandler){
		authFilter.setAuthenticationSuccessHandler(successHandler);
		return this;
	}
	
	public JwtAuthenticationConfigurer<T, B> authenticationFailureHandler(JwtAuthenticationFailureHandler failureHandler){
		authFilter.setAuthenticationFailureHandler(failureHandler);
		return this;
	}
}
