package org.tamacat.oidc.rp.util;

import java.security.SecureRandom;
import java.security.cert.CertificateException;
import java.security.cert.X509Certificate;

import javax.net.ssl.SSLContext;
import javax.net.ssl.TrustManager;
import javax.net.ssl.X509TrustManager;

import org.apache.http.conn.ssl.NoopHostnameVerifier;
import org.apache.http.conn.ssl.SSLConnectionSocketFactory;
import org.apache.http.impl.client.CloseableHttpClient;
import org.apache.http.impl.client.HttpClientBuilder;
import org.apache.http.impl.client.HttpClients;
import org.tamacat.oidc.rp.config.HttpProxyConfig;

public class HttpClientUtils {

	public static CloseableHttpClient build() {
		return build(null);
	}
	
	public static CloseableHttpClient build(HttpProxyConfig proxy) {
		HttpClientBuilder builder = null;
		if (proxy == null) {
			builder = HttpClients.custom(); 
		} else {
			builder = proxy.setProxy(HttpClients.custom());
		}
		return builder.setSSLSocketFactory(createSSLSocketFactory("TLS")).build();
	}
	
	public static SSLConnectionSocketFactory createSSLSocketFactory(String protocol) {
		SSLContext sslContext;
		try {
			sslContext = SSLContext.getInstance(protocol);
			sslContext.init(null, new TrustManager[] { createGenerousTrustManager() }, new SecureRandom());
		} catch (Exception e) {
			return null;
		}
		return new SSLConnectionSocketFactory(sslContext, NoopHostnameVerifier.INSTANCE);
	}
	
	public static X509TrustManager createGenerousTrustManager() {
		return new X509TrustManager() {
			@Override
			public void checkClientTrusted(X509Certificate[] cert, String s) throws CertificateException {
			}

			@Override
			public void checkServerTrusted(X509Certificate[] cert, String s) throws CertificateException {
			}

			@Override
			public X509Certificate[] getAcceptedIssuers() {
				return null;
			}
		};
	}
}
