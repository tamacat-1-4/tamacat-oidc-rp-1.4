package org.tamacat.oidc.rp.config;

import java.util.HashSet;
import java.util.Set;

import javax.servlet.http.HttpServletRequest;

import org.tamacat.log.Log;
import org.tamacat.log.LogFactory;
import org.tamacat.util.StringUtils;

public class FreeAccessControl {

	static final Log LOG = LogFactory.getLog(FreeAccessControl.class);
	
	protected Set<String> freeAccessExtensions = new HashSet<>();
	protected Set<String> freeAccessUrls = new HashSet<>();

	protected String path; //serviceUrl.getPath();

	public FreeAccessControl() {}
	
	public FreeAccessControl(String path) {
		setPath(path);
	}
	
	public void setPath(String path) {
		if (path != null) {
			this.path = path.trim().replaceFirst("/$", "");
		}
	}
	
	public boolean isFreeAccess(HttpServletRequest request) {
		return isFreeAccess(request.getRequestURI());
	}
	
	/**
	 * Whether it agrees to the extension or path that can be accessed without the
	 * attestation is inspected.
	 * @param urlPath
	 * @return true: contains the freeAccessExtensions or freeAccessUrl.
	 */
	public boolean isFreeAccess(String path) {
		return isFreeAccessExtension(path) || isFreeAccessUrl(path);
	}
	
	public boolean isFreeAccessExtension(String urlPath) {
		if (freeAccessExtensions.size() > 0) {
			urlPath = getPath(urlPath); //without query string
			int idx = urlPath.lastIndexOf(".");
			if (idx >= 0) {
				String ext = urlPath.substring(idx + 1, urlPath.length()).toLowerCase().trim();
				return freeAccessExtensions.contains(ext);
			}
		}
		return false;
	}

	public boolean isFreeAccessUrl(String urlPath) {
		if (this.path != null && freeAccessUrls.size() > 0) {
			urlPath = getPath(urlPath);
			for (String freeAccessUrl : freeAccessUrls) {
				if (urlPath.startsWith(this.path + "/" + freeAccessUrl)) {
					return true;
				}
			}
		}
		return false;
	}
	
	/**
	 * The extension skipping by the certification in comma seperated values.
	 * @param freeAccessExtensions (CSV)
	 */
	public void setFreeAccessExtensions(String extensions) {
		String[] list = StringUtils.split(extensions, ",");
		for (String ext : list) {
			this.freeAccessExtensions.add(ext.trim().replaceFirst("^\\.", "").toLowerCase());
		}
	}

	public void setFreeAccessUrl(String urls) {
		String[] list = StringUtils.split(urls, ",");
		for (String url : list) {
			this.freeAccessUrls.add(url.trim().replaceFirst("^/", ""));
		}
	}
	
	public Set<String> getFreeAccessExtensions() {
		return freeAccessExtensions;
	}
	
	public static String getPath(String uri) {
		int index = uri.indexOf('?');
		if (index != -1) {
			uri = uri.substring(0, index);
		} else {
			index = uri.indexOf('#');
			if (index != -1) {
				uri = uri.substring(0, index);
			}
		}
		return uri;
	}
}
