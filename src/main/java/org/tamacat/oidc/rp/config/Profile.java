package org.tamacat.oidc.rp.config;

public interface Profile {

	String val(String key);
	
	Profile val(String key, String value);
	
	String[] keys();
}
