package com.github.security.annotation;

import java.lang.annotation.ElementType;
import java.lang.annotation.Inherited;
import java.lang.annotation.Retention;
import java.lang.annotation.RetentionPolicy;
import java.lang.annotation.Target;

import org.springframework.context.annotation.Import;

import com.github.security.configuration.JwtProperties;
import com.github.security.configuration.JwtWebSecurityConfiguration;

/**
 * jwt 注解启用
 * @author zhangyf
 * 2019年8月17日
 */
@Target({ElementType.TYPE})
@Retention(RetentionPolicy.RUNTIME)
@Inherited
@Import({ JwtWebSecurityConfiguration.class, JwtProperties.class })
public @interface EnableJwtSecurity {

}
