package org.tamacat.oidc.rp.token;

import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

public interface OpenIdConnectSession {

	boolean check(HttpServletRequest req, HttpServletResponse resp);
	
	void activate(HttpServletRequest req, HttpServletResponse resp, String session);
	
	void invalidate(HttpServletRequest req, HttpServletResponse resp);
}
