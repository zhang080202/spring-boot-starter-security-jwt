package com.github.security.configuration;

import java.util.Arrays;

import org.apache.commons.lang3.StringUtils;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Qualifier;
import org.springframework.boot.autoconfigure.condition.ConditionalOnMissingBean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.authentication.AuthenticationProvider;
import org.springframework.security.config.annotation.authentication.builders.AuthenticationManagerBuilder;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.builders.WebSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configuration.WebSecurityConfigurerAdapter;
import org.springframework.security.web.authentication.logout.HttpStatusReturningLogoutSuccessHandler;
import org.springframework.security.web.header.Header;
import org.springframework.security.web.header.writers.StaticHeadersWriter;
import org.springframework.web.filter.CorsFilter;

import com.github.security.authcatication.JwtAuthenticationFailureHandler;
import com.github.security.authcatication.JwtRefreshSuccessHandler;
import com.github.security.authcatication.LoginSuccessHandler;
import com.github.security.authcatication.TokenClearLogoutHandler;
import com.github.security.filters.OptionsRequestFilter;
import com.github.security.service.JwtUserDetailsService;

@Configuration
@EnableWebSecurity
@ConditionalOnMissingBean
public class JwtWebSecurityConfiguration extends WebSecurityConfigurerAdapter {
	
	@Autowired
	private JwtUserDetailsService userDetailsService;
	
	@Autowired
	private LoginSuccessHandler loginSuccessHandler;
	
	@Autowired
	private JwtAuthenticationFailureHandler jwtAuthenticationFailureHandler;
	
	@Autowired
	@Qualifier("jwtAuthenticationProvider")
	private AuthenticationProvider jwtAuthenticationProvider;
	
	@Autowired
	@Qualifier("daoAuthenticationProvider")
	private AuthenticationProvider daoAuthenticationProvider;
	
	@Autowired
	private TokenClearLogoutHandler tokenClearLogoutHandler;
	
	@Autowired
	private JwtRefreshSuccessHandler jwtRefreshSuccessHandler;
	
	@Autowired
	private JwtConfiguration jwtConfiguration;
	
	@Override
	protected void configure(AuthenticationManagerBuilder auth) throws Exception {
		auth.authenticationProvider(jwtAuthenticationProvider)
			.authenticationProvider(daoAuthenticationProvider);
	}

	@Override
	protected void configure(HttpSecurity http) throws Exception {
		http.authorizeRequests()
	        .antMatchers(jwtConfiguration.permitUrl).permitAll()
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
		    .apply(new LoginConfigurer<>(userDetailsService)).authenticationSuccessHandler(loginSuccessHandler)
		    											     .authenticationFailureHandler(jwtAuthenticationFailureHandler)
		    .and()
		    .apply(new JwtAuthenticationConfigurer<>())
		    	.authenticationSuccessHandler(jwtRefreshSuccessHandler)
		    	.authenticationFailureHandler(jwtAuthenticationFailureHandler)
		    	.permissiveRequestUrls(getPermitUrls())
		    .and()
		    .logout()
		        .addLogoutHandler(tokenClearLogoutHandler)
		        .logoutSuccessHandler(new HttpStatusReturningLogoutSuccessHandler())
		    .and()
		    .sessionManagement().disable();
	}
	
}
