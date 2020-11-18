/*
 * Copyright 2019 tamacat.org
 * All rights reserved.
 */
package org.tamacat.oidc.rp.config;

import static org.junit.Assert.*;

import java.util.Map;

import org.junit.Test;
import org.tamacat.log.Log;
import org.tamacat.log.LogFactory;

public class OpenIdConnectConfigLoaderTest {

	static final Log LOG = LogFactory.getLog(OpenIdConnectConfigLoaderTest.class);
	
	@Test
	public void testLoad() {
		OpenIdConnectConfigLoader loader = new OpenIdConnectConfigLoader();
		Map<String, OpenIdConnectConfig> configs = loader.load("openid-connect-config.json");
		//for (OpenIdConnectConfig config : configs.values()) {
		//	LOG.debug(config);
		//}

		OpenIdConnectConfig config = configs.get("test01.example.com");
		assertEquals("http://sso.example.local/oauth2/authorize", config.getAuthorizationEndpoint());
		assertEquals("http://sso.example.local/oauth2/token", config.getTokenEndpoint());
		
		Profile profile = config.getProfile();

		assertEquals("user_name", profile.keys()[0]);
		assertEquals("email", profile.keys()[1]);
		
		//proxy
		assertEquals("http://localhost:3128", config.getProxyConfig().getProxyHttpHost().toURI());
		assertEquals("username", config.getProxyConfig().getCredentials().getUserPrincipal().getName());
		assertEquals("password", config.getProxyConfig().getCredentials().getPassword());
		assertEquals("localhost, *.local", config.getProxyConfig().getNonProxyHosts());
	}

}
