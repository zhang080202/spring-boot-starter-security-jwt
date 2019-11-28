package com.github.security.exception;

import org.springframework.security.core.AuthenticationException;

public class JwtExpireException extends AuthenticationException {

	private static final long serialVersionUID = 1L;

	public JwtExpireException(String msg) {
		super(msg);
	}

	public JwtExpireException(String msg, Throwable t) {
		super(msg, t);
	}
	
}
