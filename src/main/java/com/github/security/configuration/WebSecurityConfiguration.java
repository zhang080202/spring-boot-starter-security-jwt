package com.github.security.configuration;

import java.util.Arrays;

import org.apache.commons.lang3.StringUtils;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.authentication.AuthenticationProvider;
import org.springframework.security.authentication.dao.DaoAuthenticationProvider;
import org.springframework.security.config.annotation.authentication.builders.AuthenticationManagerBuilder;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.builders.WebSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configuration.WebSecurityConfigurerAdapter;
import org.springframework.security.core.userdetails.UserCache;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.web.authentication.logout.HttpStatusReturningLogoutSuccessHandler;
import org.springframework.security.web.header.Header;
import org.springframework.security.web.header.writers.StaticHeadersWriter;
import org.springframework.web.cors.CorsConfiguration;
import org.springframework.web.cors.CorsConfigurationSource;
import org.springframework.web.cors.UrlBasedCorsConfigurationSource;
import org.springframework.web.filter.CorsFilter;

import com.github.security.authcatication.JwtAuthenticationProvider;
import com.github.security.authcatication.JwtRefreshSuccessHandler;
import com.github.security.authcatication.LoginSuccessHandler;
import com.github.security.authcatication.TokenClearLogoutHandler;
import com.github.security.filters.OptionsRequestFilter;
import com.github.security.service.JwtUserDetailsService;

@Configuration
@EnableWebSecurity
public class WebSecurityConfiguration extends WebSecurityConfigurerAdapter {
	
	@Autowired
	private JwtUserDetailsService userDetailsService;
	
	@Autowired(required = false)
	private UserCache userCache;
	
	@Autowired
	private JwtProperties p;
	
	private static final String DEFAULT_PERMITURL = "/login/**,/logout/**";

	@Override
	protected void configure(AuthenticationManagerBuilder auth) throws Exception {
		auth.authenticationProvider(getJwtAuthenticationProvider())
			.authenticationProvider(getDaoAuthenticationProvider());
	}

	@Override
	public void configure(WebSecurity web) throws Exception {
		super.configure(web);
	}

	@Override
	protected void configure(HttpSecurity http) throws Exception {
		http.authorizeRequests()
	        .antMatchers(getPermitUrls()).permitAll()
	        .anyRequest().authenticated()
	        .and()
		    .csrf().disable()
		    .formLogin().disable()
		    .sessionManagement().disable()
		    .cors()
		    .and()
		    .headers().addHeaderWriter(new StaticHeadersWriter(Arrays.asList(
		    		new Header("Access-control-Allow-Origin","*"),
		    		new Header("Access-Control-Expose-Headers","Authorization"))))
		    .and()
		    .addFilterAfter(new OptionsRequestFilter(), CorsFilter.class)
		    .apply(new LoginConfigurer<>(userDetailsService)).authenticationSuccessHandler(loginSuccessHandler())
		    .and()
		    .apply(new JwtAuthenticationConfigurer<>())
		    	.authenticationSuccessHandler(jwtRefreshSuccessHandler())
		    	.permissiveRequestUrls(getPermitUrls())
		    .and()
		    .logout()
		        .addLogoutHandler(tokenClearLogoutHandler())
		        .logoutSuccessHandler(new HttpStatusReturningLogoutSuccessHandler())
		    .and()
		    .sessionManagement().disable();
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
	protected JwtRefreshSuccessHandler jwtRefreshSuccessHandler() {
		JwtRefreshSuccessHandler refreshSuccessHandler = new JwtRefreshSuccessHandler(userDetailsService);
		refreshSuccessHandler.setTokenRefreshInterval(p.getTokenRefreshInterval());
		return refreshSuccessHandler;
	}
	
	@Bean 
	public LoginSuccessHandler loginSuccessHandler() {
		return new LoginSuccessHandler(userDetailsService);
	}
	
	@Bean
	public TokenClearLogoutHandler tokenClearLogoutHandler() {
		return new TokenClearLogoutHandler(userDetailsService);
	}
	
	String[] getPermitUrls() {
		String urls = p.getPermitUrls() + DEFAULT_PERMITURL;
		return StringUtils.split(urls.trim(), ",");
	}
	
	@Bean
	protected CorsConfigurationSource corsConfigurationSource() {
		CorsConfiguration configuration = new CorsConfiguration();
		configuration.setAllowedOrigins(Arrays.asList("*"));
		configuration.setAllowedMethods(Arrays.asList("GET","POST","DELETE","PUT","HEAD", "OPTION"));
		configuration.setAllowedHeaders(Arrays.asList("*"));
		configuration.addExposedHeader("Authorization");
		UrlBasedCorsConfigurationSource source = new UrlBasedCorsConfigurationSource();
		source.registerCorsConfiguration("/**", configuration);
		return source;
	}
	
}
