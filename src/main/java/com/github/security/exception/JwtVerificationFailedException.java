package com.github.security.exception;

import org.springframework.security.core.AuthenticationException;

public class JwtVerificationFailedException extends AuthenticationException {

	private static final long serialVersionUID = 1L;

	public JwtVerificationFailedException(String msg) {
		super(msg);
	}

}
