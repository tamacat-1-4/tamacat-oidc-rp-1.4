/*
 * Copyright 2019 tamacat.org
 * All rights reserved.
 */
package org.tamacat.oidc.rp.util;

import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.util.Base64;

/**
 * RFC7636 PKCE https://tools.ietf.org/html/rfc7636
 */
public class PKCEUtils {

	//BASE64URL-ENCODE(SHA256(ASCII(code_verifier)))
	public static String generateCodeChallenge(String codeVerifier, String codeChallengeMethod) {
		if ("S256".equalsIgnoreCase(codeChallengeMethod)) {
			try {
				MessageDigest md = MessageDigest.getInstance("SHA-256");
				byte[] digest = md.digest(codeVerifier.getBytes());
				return Base64.getUrlEncoder().withoutPadding().encodeToString(digest);
			} catch (NoSuchAlgorithmException e) {
				throw new IllegalArgumentException("No such algorithm.", e);
			}
		} else {
			return codeVerifier;
		}
	}
}
