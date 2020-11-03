/*
 * Copyright 2019 tamacat.org
 * All rights reserved.
 */
package org.tamacat.oidc.rp.filter;

import java.io.IOException;
import java.math.BigInteger;
import java.security.KeyFactory;
import java.security.interfaces.RSAPublicKey;
import java.security.spec.RSAPublicKeySpec;
import java.security.spec.X509EncodedKeySpec;
import java.util.Arrays;
import java.util.Base64;
import java.util.List;
import java.util.Map;

import javax.json.Json;
import javax.json.JsonArray;
import javax.json.JsonObject;
import javax.json.JsonReader;
import javax.servlet.Filter;
import javax.servlet.FilterChain;
import javax.servlet.FilterConfig;
import javax.servlet.ServletException;
import javax.servlet.ServletRequest;
import javax.servlet.ServletResponse;
import javax.servlet.http.Cookie;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

import org.apache.http.HttpResponse;
import org.apache.http.client.methods.HttpGet;
import org.tamacat.auth.util.EncryptSessionUtils;
import org.tamacat.di.DI;
import org.tamacat.log.Log;
import org.tamacat.log.LogFactory;
import org.tamacat.mvc.error.ForbiddenException;
import org.tamacat.mvc.error.ServiceUnavailableException;
import org.tamacat.mvc.error.UnauthorizedException;
import org.tamacat.oidc.rp.config.FreeAccessControl;
import org.tamacat.oidc.rp.config.HttpProxyConfig;
import org.tamacat.oidc.rp.config.OpenIdConnectConfig;
import org.tamacat.oidc.rp.config.OpenIdConnectConfigLoader;
import org.tamacat.oidc.rp.token.AccessTokenExpiredException;
import org.tamacat.oidc.rp.token.AuthorizationCodeTokenRequest2;
import org.tamacat.oidc.rp.token.OpenIdConnectSession;
import org.tamacat.oidc.rp.util.HttpClientUtils;
import org.tamacat.oidc.rp.util.PKCEUtils;
import org.tamacat.util.CollectionUtils;
import org.tamacat.util.EncryptionUtils;
import org.tamacat.util.StringUtils;

import com.google.api.client.auth.oauth2.AuthorizationCodeRequestUrl;
import com.google.api.client.auth.oauth2.TokenResponse;
import com.google.api.client.auth.oauth2.TokenResponseException;
import com.google.api.client.auth.openidconnect.IdToken;
import com.google.api.client.http.GenericUrl;
import com.google.api.client.http.HttpTransport;
import com.google.api.client.http.javanet.NetHttpTransport;
import com.google.api.client.json.JsonFactory;
import com.google.api.client.json.jackson2.JacksonFactory;

public class OpenIdConnectBasicClientFilter implements Filter {

	static Log LOG = LogFactory.getLog(OpenIdConnectBasicClientFilter.class);

	static final String SKIP_SERVLET = "OpenIdConnectBasicClientFilter.SKIP_SERVLET";
	
	static final String REQUEST_CONTEXT_TID = "tid";
	static final String REQUEST_CONTEXT_UPN = "upn";
	
	protected FreeAccessControl freeAccessControl = new FreeAccessControl();

	protected String singleSignOnCookieName = "SSOSession";
	protected String singleSignOnCookiePath = "/";
	protected boolean isHttpOnlyCookie = true;
	protected boolean isSecureCookie;
	protected boolean useForwardedProto;
	
	protected HttpTransport httpTransport = new NetHttpTransport();
	protected JsonFactory jsonFactory = new JacksonFactory();

	protected List<String> scopes = Arrays.asList("openid", "email", "profile");
	protected List<String> responseTypes = Arrays.asList("code");
	protected String callbackPath = "oauth2callback";
	
	protected OpenIdConnectConfig openIdConnectConfig;
	protected HttpProxyConfig httpProxyConfig;
	protected OpenIdConnectSession authentication;
	protected String logoutPath = "/logout";
	protected String configureFile = "controller.xml";

	static final Map<String, RSAPublicKey> PUBLIC_KEY_CACHE = CollectionUtils.newHashMap();
	
	public OpenIdConnectBasicClientFilter() {
		this.openIdConnectConfig = new OpenIdConnectConfigLoader().loadOpenIdConnectConfig("openid-connect.json");
	}

	@Override
	public void init(FilterConfig filterConfig) throws ServletException {
		this.freeAccessControl.setPath(filterConfig.getServletContext().getContextPath());
		String configureFile = filterConfig.getInitParameter("configureFile");
		if (StringUtils.isNotEmpty(configureFile)) {
			this.configureFile = configureFile;
		}
		String auth = filterConfig.getInitParameter("OpenIdConnectSessionID");
		if (StringUtils.isNotEmpty(auth)) {
			setOpenIdConnectSession(DI.configure(this.configureFile).getBean(auth, OpenIdConnectSession.class));
		}
		
		String useForwardedProto = filterConfig.getInitParameter("useForwardedProto");
		if (StringUtils.isNotEmpty(useForwardedProto)) {
			setUseForwardedProto(Boolean.valueOf(useForwardedProto));
		}
		String logoutPath = filterConfig.getInitParameter("logoutPath");
		if (StringUtils.isNotEmpty(logoutPath)) {
			setLogoutPath(logoutPath); 
		}
	}

	@Override
	public void doFilter(ServletRequest request, ServletResponse response, FilterChain chain)
			throws IOException, ServletException {
		doFilter((HttpServletRequest)request, (HttpServletResponse)response);
		if (StringUtils.isNotEmpty(request.getAttribute(SKIP_SERVLET)) == false) {
			chain.doFilter(request, response);
		}
	}

	@Override
	public void destroy() {		
	}

	public void setOpenIdConnectSession(OpenIdConnectSession authentication) {
		this.authentication = authentication;
	}
	
	/**
	 * Set proxy configuration, access to ID provider through a HTTP Proxy.
	 * @param httpProxyConfig
	 */
	public void setHttpProxyConfig(HttpProxyConfig httpProxyConfig) {
		this.httpProxyConfig = httpProxyConfig;
		if (httpProxyConfig != null) {
			httpProxyConfig.setProxy();
		}
	}

	public void setScope(String scope) {
		scopes = Arrays.asList(StringUtils.split(scope, ","));
	}

	public void setResponseTypes(String type) {
		responseTypes = Arrays.asList(StringUtils.split(type, ","));
	}

	public void setCallbackPath(String callbackPath) {
		this.callbackPath = callbackPath;
	}
	
	public void setFreeAccessExtensions(String freeAccessExtensions) {
		this.freeAccessControl.setFreeAccessExtensions(freeAccessExtensions);
	}

	public void setFreeAccessUrl(String freeAccessUrl) {
		this.freeAccessControl.setFreeAccessUrl(freeAccessUrl);
	}
	
	public void setLogoutPath(String logoutPath) {
		this.logoutPath = logoutPath;
	}

	public void setOpenIdConnectConfig(String file) {
		openIdConnectConfig = new OpenIdConnectConfigLoader().loadOpenIdConnectConfig(file);
	}

	protected String getClientId(HttpServletRequest req) {
		return openIdConnectConfig.getClientId();
	}

	public void doFilter(HttpServletRequest req, HttpServletResponse resp) {
		String uri = req.getRequestURI();
		LOG.info(uri);
		//Free access or login URI (do not required authorization)
		if (freeAccessControl.isFreeAccess(uri)) {
			return;
		}
		//redirect logout
		if (uri.startsWith(req.getContextPath()+logoutPath)) {
			LOG.debug("logout");
			handleLogoutRequest(req, resp);
			return;
		}
		
		//redirect callback endpoint
		if (uri.indexOf("/"+ callbackPath) >= 0) {
			callback(req, resp);
			return;
		}
		
		//session check
		boolean session = check(req, resp);
		//LOG.debug("ALREADY LOGIN SESSION CHECK session="+session);
		if (session) {
			LOG.debug("session="+session);
			return;
		}

		// The OAuth2.0 Authorization Framework: Bearer Token Usage
		String authHeader = req.getHeader("Authorization");
		if (StringUtils.isNotEmpty(authHeader)) {
			String[] credentials = StringUtils.split(authHeader, " ");
			if (credentials.length == 2 && "Bearer".equals(credentials[0])) {
				String b64token = credentials[1];
				LOG.debug("Authorization: Bearer " + b64token);
				try {
					IdToken idToken = IdToken.parse(jsonFactory, b64token);
					LOG.debug("IdToken=" + idToken);
					String kid = idToken.getHeader().getKeyId();
					RSAPublicKey publicKey = getPublicKey(openIdConnectConfig.getJwksUri(), kid);
					if (publicKey == null) {
						LOG.warn("IdToken verify Unkown (PublicKey not found.) kid=" + kid);
					} else if (idToken.verifySignature(publicKey)) {
						String tid = (String) idToken.getPayload().get("tid");
						String upn = (String) idToken.getPayload().get("upn");
						LOG.debug("IdToken verify OK");
						LOG.debug("jwt=" + idToken.getPayload());
						LOG.debug("tid=" + tid);
						LOG.debug("upn=" + upn);
						req.setAttribute(REQUEST_CONTEXT_TID, tid);
						req.setAttribute(REQUEST_CONTEXT_UPN, upn);
					} else {
						LOG.debug("IdToken verify NG");
					}
				} catch (Exception e) {
					e.printStackTrace();
					throw new UnauthorizedException();
				}
				return;
			}
			throw new UnauthorizedException();
		} else {
			redirectAuthorizationEndpoint(req, resp);
			// handleLoginErrorRequest(req, resp, context);
		}
	}

	protected boolean check(HttpServletRequest req, HttpServletResponse resp) {
		return authentication.check(req, resp);
	}

	protected void handleLogoutRequest(HttpServletRequest req, HttpServletResponse resp) {
		String logoutUri = openIdConnectConfig.getEndSessionEndpoint();
		String redirectUri = getOriginURL(req, openIdConnectConfig.getRedirectUri());
		LOG.debug("Redirect-> "+logoutUri);
		
		authentication.invalidate(req, resp);
		
		setCookieExpires(resp, singleSignOnCookieName, singleSignOnCookiePath);
		setCookieExpires(resp, "upn", singleSignOnCookiePath);
		setCookieExpires(resp, "subject", singleSignOnCookiePath);
				
		if (StringUtils.isNotEmpty(logoutUri)) {
			//redirect OP logout.
			sendRedirect(req, resp, logoutUri+"?redirect="+EncryptSessionUtils.encryptSession(redirectUri));
		}
	}

	protected String getUrlforCodeFlowAuth(HttpServletRequest req, String redirectUri) {
		String clientId = getClientId(req);
		AuthorizationCodeRequestUrl codeUrl = new AuthorizationCodeRequestUrl(
			openIdConnectConfig.getAuthorizationEndpoint(), clientId)
			.setRedirectUri(redirectUri).setScopes(scopes).setResponseTypes(responseTypes);
		
		//RFC 7636 PKCE (Proof Key for Code Exchange by OAuth Public Clients)
		String codeChallengeMethod = "S256";
		String codeVerifier = getCodeVerifier(clientId+"/"+redirectUri);
		String codeChallenge = PKCEUtils.generateCodeChallenge(codeVerifier, codeChallengeMethod);
		codeUrl.set("code_challenge_method", "S256").set("code_challenge", codeChallenge);
		return codeUrl.build();
	}
	
	protected void redirectAuthorizationEndpoint(HttpServletRequest req, HttpServletResponse resp) {
		String authUrl = getUrlforCodeFlowAuth(req, getOriginURL(req, openIdConnectConfig.getCallbackUri()));
		sendRedirect(req, resp, authUrl);
	}

	protected void sendRedirect(HttpServletRequest req, HttpServletResponse resp, String uri) {
		LOG.debug("Redirect-> "+uri);
		resp.setHeader("Location", uri);
		resp.setStatus(302);
		req.setAttribute(SKIP_SERVLET, Boolean.TRUE);
	}

	protected void callback(HttpServletRequest req, HttpServletResponse resp) {
		String code = req.getParameter("code");
		String error = req.getParameter("error");
		String errorDescription = req.getParameter("error_description");
		if (StringUtils.isNotEmpty(error) && StringUtils.isNotEmpty(errorDescription)) {
			LOG.warn("Error="+error+", Description="+errorDescription.replace("\r", "").replace("\n", ","));
			if (code == null) {
				throw new ForbiddenException("Access Denied.");
			}
		}
		LOG.debug("#callback code=" + code);
		String nonce = null; //UniqueCodeGenerator.generate();
		try {
			TokenResponse tr = getTokenResponse(req, code, nonce);
			processTokenResponse(req, resp, tr, nonce);
		} catch (AccessTokenExpiredException e) {
			redirectAuthorizationEndpoint(req, resp);
			//throw e;
		} catch (UnauthorizedException e) {
			e.printStackTrace();
			throw e;
		} catch (Exception e) {
			e.printStackTrace();
			throw new ServiceUnavailableException(e.getMessage(), e);
		}
	}

	public TokenResponse getTokenResponse(HttpServletRequest req, String code, String nonce) {
		if (StringUtils.isEmpty(code)) {
			return null;
		}
		AuthorizationCodeTokenRequest2 tokenUrl = new AuthorizationCodeTokenRequest2(
			httpTransport, jsonFactory, new GenericUrl(openIdConnectConfig.getTokenEndpoint()), code);
		String clientId = getClientId(req);
		String redirectUri = getOriginURL(req, openIdConnectConfig.getCallbackUri());
		
		tokenUrl.setGrantType("authorization_code");
		tokenUrl.setRedirectUri(redirectUri);
		tokenUrl.set("client_id", clientId);
		tokenUrl.set("client_secret", openIdConnectConfig.getClientSecret());
		tokenUrl.set("code_verifier", getCodeVerifier(clientId+"/"+redirectUri)); //PKCE
		if (StringUtils.isNotEmpty(nonce)) {
			tokenUrl.set("nonce", nonce);
		}

		LOG.debug("tokenUrl=" + tokenUrl.toString());

		try {
			return tokenUrl.execute2();
		} catch (TokenResponseException e) {
			throw new AccessTokenExpiredException(e);
		} catch (Exception e) {
			throw new ServiceUnavailableException(e.getMessage(), e);
		}
	}

	protected void processTokenResponse(HttpServletRequest req, HttpServletResponse resp, TokenResponse tokenResponse, String nonce) {
		IdToken idToken = getIdToken(tokenResponse);
		
		//if (StringUtils.isNotEmpty(nonce) && nonce.equals(idToken.getPayload().getNonce())==false) {
		//	throw new AccessTokenException("Invalid IdToken. Illegal nonce parameter.");
		//}
		
		String upn = null;
		if ("subject".equals(openIdConnectConfig.getUpn())) {
			upn = (String) idToken.getPayload().getSubject();
		} else {
			upn = (String) idToken.getPayload().get(openIdConnectConfig.getUpn());
		}
		String sub = idToken.getPayload().getSubject();

		LOG.debug("upn="+upn+" ,subject=" + sub);
		
		//resp.addHeader("Set-Cookie", "sid="+id+"; HttpOnly=true; Path=/"); //domain or sid
		// if local user is not exists when redirect user register URL.
		//resp.addHeader("Set-Cookie", singleSignOnCookieName + "=" + new String(Base64.getUrlEncoder().encode(id.getBytes())) + "; HttpOnly=true; Path=/");
		if (upn != null) {
			setCookie(resp, "upn", new String(Base64.getUrlEncoder().encode(upn.getBytes())), singleSignOnCookiePath);
		} else {
			String email = (String)idToken.getPayload().get("email");
			if (email != null) {
				setCookie(resp, "upn", new String(Base64.getUrlEncoder().encode(email.getBytes())), singleSignOnCookiePath);
			}
		}
		setCookie(resp, "subject", new String(Base64.getUrlEncoder().encode(sub.getBytes())), singleSignOnCookiePath);

		authentication.activate(req, resp, upn, openIdConnectConfig.getId());
		
		sendRedirect(req, resp, getOriginURL(req, openIdConnectConfig.getRedirectUri()));
	}
	
	protected String getCodeVerifier(String secret) {
		return EncryptionUtils.getMessageDigest(EncryptSessionUtils.encryptSession(secret), "SHA-256");
	}
	
	public IdToken getIdToken(TokenResponse tokenResponse) {
		if (tokenResponse != null) {
			String value = (String) tokenResponse.get("id_token");
			LOG.debug("id_token=" + value);
			try {
				IdToken idToken = IdToken.parse(jsonFactory, value);
				LOG.debug("id_token=" + idToken);
				return idToken;
			} catch (Exception e) {
				throw new ServiceUnavailableException(e.getMessage(), e);
			}
		}
		return null;
	}

	protected RSAPublicKey getPublicKey(String jwksUri, String kid) {
		if (StringUtils.isEmpty(jwksUri) || StringUtils.isEmpty(kid)) {
			return null;
		}
		String key = jwksUri+"/"+kid;
		RSAPublicKey publicKey = PUBLIC_KEY_CACHE.get(key);
		if (publicKey == null) {
			RSAPublicKey getPublicKey = getPublicKeyFromDiscoveryKeys(jwksUri, kid);
			if (getPublicKey != null) {
				PUBLIC_KEY_CACHE.put(key, getPublicKey);
				LOG.debug(getPublicKey);
				return getPublicKey;
			}
		}
		return publicKey;
	}
	
	protected RSAPublicKey getPublicKeyFromDiscoveryKeys(String jwksUri, String id) {
		String n = null;
		String e = null;
		HttpGet req = new HttpGet(jwksUri);
		LOG.debug(req);
		try {
			HttpResponse resp = HttpClientUtils.build(httpProxyConfig).execute(req);
			JsonReader r = Json.createReader(resp.getEntity().getContent());
			JsonObject json = r.readObject();
			JsonArray keys = json.getJsonArray("keys");
			
			for (int i=0; i<keys.size(); i++) {
				JsonObject key = keys.getJsonObject(i);
				if (id.equals(key.getString("kid"))) {
					n = key.getString("n");
					e = key.getString("e");
					break;
				}
			}
		} catch (Exception ex) {
			ex.printStackTrace();
			return null;
		}
		if (StringUtils.isNotEmpty(n)) {
			return getRSAPublicKey(n, e);
		} else {
			return null;
		}
	}
	
	protected RSAPublicKey getRSAPublicKey(String x5c) {
		try {
			X509EncodedKeySpec spec = new X509EncodedKeySpec(Base64.getUrlDecoder().decode(x5c));
			return (RSAPublicKey) KeyFactory.getInstance("RSA").generatePublic(spec);
		} catch (Exception ex) {
			ex.printStackTrace();
		}
		return null;
	}
	
	protected RSAPublicKey getRSAPublicKey(String n, String e) {
		try {
			BigInteger modulus = new BigInteger(1, Base64.getUrlDecoder().decode(n));
			BigInteger publicExponent = new BigInteger(1, Base64.getUrlDecoder().decode(e));
			return (RSAPublicKey)KeyFactory.getInstance("RSA").generatePublic(new RSAPublicKeySpec(modulus, publicExponent));
		} catch (Exception ex) {
			ex.printStackTrace();
		}
		return null;
	}
	
	protected void setCookie(HttpServletResponse resp, String key, String value, String path) {
		Cookie cookie = new Cookie(key, value);
		cookie.setPath(path);
		cookie.setSecure(isSecureCookie);
		cookie.setHttpOnly(isHttpOnlyCookie);
		resp.addCookie(cookie);
	}
	
	protected void setCookieExpires(HttpServletResponse resp, String key, String path) {
		Cookie cookie = new Cookie(key, "");
		cookie.setMaxAge(0);
		cookie.setPath(path);
		cookie.setSecure(isSecureCookie);
		cookie.setHttpOnly(isHttpOnlyCookie);
		resp.addCookie(cookie);
	}
	
	public void setSingleSignOnCookiePath(String singleSignOnCookiePath) {
		this.singleSignOnCookiePath = singleSignOnCookiePath;
	}
	
	public void setHttpOnlyCookie(boolean isHttpOnlyCookie) {
		this.isHttpOnlyCookie = isHttpOnlyCookie;
	}
	
	public void setSecureCookie(boolean isSecureCookie) {
		this.isSecureCookie = isSecureCookie;
	}
	
	public void setUseForwardedProto(boolean useForwardedProto) {
		this.useForwardedProto = useForwardedProto;
	}
	
	protected String getOriginURL(HttpServletRequest req, String url) {
		if (useForwardedProto) {
			String proto = req.getHeader("X-Forwarded-Proto");
			if ("http".equalsIgnoreCase(proto)) {
				return url.replaceFirst("^https://","http://");
			}
		}
		return url;
	}
}
