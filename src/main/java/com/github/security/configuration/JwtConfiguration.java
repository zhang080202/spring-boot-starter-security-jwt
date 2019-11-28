package com.github.security.configuration;

import java.util.Arrays;

import org.apache.commons.lang3.StringUtils;
import org.springframework.beans.factory.InitializingBean;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.autoconfigure.AutoConfigureBefore;
import org.springframework.boot.autoconfigure.condition.ConditionalOnMissingBean;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.authentication.AuthenticationProvider;
import org.springframework.security.authentication.dao.DaoAuthenticationProvider;
import org.springframework.security.core.userdetails.UserCache;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.web.cors.CorsConfiguration;
import org.springframework.web.cors.CorsConfigurationSource;
import org.springframework.web.cors.UrlBasedCorsConfigurationSource;

import com.github.security.authcatication.JwtAuthenticationFailureHandler;
import com.github.security.authcatication.JwtAuthenticationProvider;
import com.github.security.authcatication.JwtRefreshSuccessHandler;
import com.github.security.authcatication.LoginSuccessHandler;
import com.github.security.authcatication.TokenClearLogoutHandler;
import com.github.security.service.JwtUserDetailsService;

@Configuration
@AutoConfigureBefore({ JwtWebSecurityConfiguration.class })
public class JwtConfiguration implements InitializingBean {
	
	private static final String DEFAULT_PERMITURL = "/login/**,/logout/**";
	
	@Autowired
	private JwtUserDetailsService userDetailsService;
	
	@Autowired
	private JwtProperties p;
	
	@Autowired(required = false)
	private UserCache userCache;
	
	public String[] permitUrl;
	
	@Bean
	@ConditionalOnMissingBean(JwtRefreshSuccessHandler.class)
	protected JwtRefreshSuccessHandler jwtRefreshSuccessHandler() {
		JwtRefreshSuccessHandler refreshSuccessHandler = new JwtRefreshSuccessHandler(userDetailsService);
		refreshSuccessHandler.setTokenRefreshInterval(p.getTokenRefreshInterval());
		return refreshSuccessHandler;
	}
	
	@Bean 
	@ConditionalOnMissingBean(LoginSuccessHandler.class)
	public LoginSuccessHandler loginSuccessHandler() {
		return new LoginSuccessHandler(userDetailsService);
	}
	
	@Bean
	@ConditionalOnMissingBean(JwtAuthenticationFailureHandler.class)
	public JwtAuthenticationFailureHandler jJwtAuthenticationFailureHandler() {
		return new JwtAuthenticationFailureHandler();
	}
	
	@Bean
	@ConditionalOnMissingBean(TokenClearLogoutHandler.class)
	public TokenClearLogoutHandler tokenClearLogoutHandler() {
		return new TokenClearLogoutHandler(userDetailsService);
	}
	
	
	@Bean("jwtAuthenticationProvider")
	public AuthenticationProvider getJwtAuthenticationProvider() {
		JwtAuthenticationProvider authenticationProvider = new JwtAuthenticationProvider();
		authenticationProvider.setUserDetailsService(userDetailsService);
		if (userCache != null) {
			authenticationProvider.setUserCache(userCache);
		}
		return authenticationProvider;
	}
	
	@Bean("daoAuthenticationProvider")
	protected AuthenticationProvider getDaoAuthenticationProvider() throws Exception{
		DaoAuthenticationProvider daoProvider = new DaoAuthenticationProvider();
		daoProvider.setUserDetailsService(userDetailsService);
		daoProvider.setPasswordEncoder(new BCryptPasswordEncoder());
		return daoProvider;
	}
	
	@Bean
	@ConditionalOnMissingBean
	protected CorsConfigurationSource corsConfigurationSource() {
		CorsConfiguration configuration = new CorsConfiguration();
		configuration.setAllowCredentials(true);
		configuration.setAllowedOrigins(Arrays.asList("*"));
		configuration.setAllowedMethods(Arrays.asList("GET","POST","DELETE","PUT","HEAD", "OPTION"));
		configuration.setAllowedHeaders(Arrays.asList("*"));
		configuration.addExposedHeader("Authorization");
		UrlBasedCorsConfigurationSource source = new UrlBasedCorsConfigurationSource();
		source.registerCorsConfiguration("/**", configuration);
		return source;
	}
	
	public void setUserCache(UserCache userCache) {
		this.userCache = userCache;
	}

	@Override
	public void afterPropertiesSet() throws Exception {
		permitUrl = getPermitUrls();
	}
	

	String[] getPermitUrls() {
		String urls = p.getPermitUrls() + "," + DEFAULT_PERMITURL;
		
		String[] strs = StringUtils.split(urls.trim(), ",");
		for (int i = 0; i < strs.length; i++) {
			strs[i] = strs[i].trim();
		}
		
		return StringUtils.split(urls.trim(), ",");
	}
}
