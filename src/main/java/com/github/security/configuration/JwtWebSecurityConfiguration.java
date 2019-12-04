package com.github.security.configuration;

import java.util.Arrays;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Qualifier;
import org.springframework.boot.autoconfigure.condition.ConditionalOnMissingBean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.authentication.AuthenticationProvider;
import org.springframework.security.config.annotation.authentication.builders.AuthenticationManagerBuilder;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configuration.WebSecurityConfigurerAdapter;
import org.springframework.security.web.authentication.logout.HttpStatusReturningLogoutSuccessHandler;
import org.springframework.security.web.header.Header;
import org.springframework.security.web.header.writers.StaticHeadersWriter;
import org.springframework.web.filter.CorsFilter;

import com.github.security.filters.OptionsRequestFilter;
import com.github.security.handler.JwtAuthenticationFailureHandler;
import com.github.security.handler.JwtRefreshSuccessHandler;
import com.github.security.handler.LoginSuccessHandler;
import com.github.security.handler.LogoutBlacklistHandler;
import com.github.security.handler.TokenClearLogoutHandler;
import com.github.security.service.JwtUserDetailsService;

@Configuration
@EnableWebSecurity
@ConditionalOnMissingBean(JwtWebSecurityConfiguration.class)
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
	private LogoutBlacklistHandler logoutBlacklistHandler;
	
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
		    	.permissiveRequestUrls(jwtConfiguration.getPermitUrls())
		    .and()
		    .logout()
		        .addLogoutHandler(tokenClearLogoutHandler)
		        .addLogoutHandler(logoutBlacklistHandler)
		        .logoutSuccessHandler(new HttpStatusReturningLogoutSuccessHandler())
		    .and()
		    .sessionManagement().disable();
	}
	
}
