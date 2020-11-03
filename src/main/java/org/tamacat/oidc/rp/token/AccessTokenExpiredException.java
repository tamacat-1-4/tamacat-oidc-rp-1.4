/*
 * Copyright 2019 tamacat.org
 * All rights reserved.
 */
package org.tamacat.oidc.rp.token;

public class AccessTokenExpiredException extends RuntimeException {

	private static final long serialVersionUID = 1L;

	public AccessTokenExpiredException() {}

	public AccessTokenExpiredException(String message, Throwable cause, boolean enableSuppression,
			boolean writableStackTrace) {
		super(message, cause, enableSuppression, writableStackTrace);
	}

	public AccessTokenExpiredException(String message, Throwable cause) {
		super(message, cause);
	}

	public AccessTokenExpiredException(String message) {
		super(message);
	}

	public AccessTokenExpiredException(Throwable cause) {
		super(cause);
	}
}
