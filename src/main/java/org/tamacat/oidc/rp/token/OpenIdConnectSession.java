/*
 * Copyright 2019 tamacat.org
 * All rights reserved.
 */
package org.tamacat.oidc.rp.token;

import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

public interface OpenIdConnectSession {

	boolean check(HttpServletRequest req, HttpServletResponse resp);
	
	void activate(HttpServletRequest req, HttpServletResponse resp, String upn, String provider);
	
	void invalidate(HttpServletRequest req, HttpServletResponse resp);
}
