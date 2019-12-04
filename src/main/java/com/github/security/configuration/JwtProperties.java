package com.github.security.configuration;

import org.springframework.boot.context.properties.ConfigurationProperties;

@ConfigurationProperties(prefix = "jwt.security")
public class JwtProperties {

	private String permitUrls; //请求白名单 以逗号分隔

	private int tokenRefreshInterval; // token刷新时间
	
	private int clearInterval = 60000; // 黑名单清理时间

	public String getPermitUrls() {
		return permitUrls;
	}

	public void setPermitUrls(String permitUrls) {
		this.permitUrls = permitUrls;
	}

	public int getTokenRefreshInterval() {
		return tokenRefreshInterval;
	}

	public void setTokenRefreshInterval(int tokenRefreshInterval) {
		this.tokenRefreshInterval = tokenRefreshInterval;
	}

	public int getClearInterval() {
		return clearInterval;
	}

	public void setClearInterval(int clearInterval) {
		this.clearInterval = clearInterval;
	}

}
