package com.github.security.configuration;

import org.springframework.boot.autoconfigure.condition.ConditionalOnClass;
import org.springframework.boot.context.properties.EnableConfigurationProperties;
import org.springframework.context.annotation.Configuration;
import org.springframework.context.annotation.Import;

import com.github.security.annotation.EnableJwtSecurity;

/**
 * 
 * @author zhangyf
 * 2019年11月27日
 * Jwt 自动配置类
 */
@Configuration
@ConditionalOnClass({ EnableJwtSecurity.class })
@EnableConfigurationProperties(JwtProperties.class)
@Import({ JwtWebSecurityConfiguration.class, JwtConfiguration.class, ScheduleConfiguration.class})
public class JwtAutoConfiguration {

}
