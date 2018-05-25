package com.goodbyeq.user.bo;

import java.util.Map;

public class GBQUserDTO {
	
	private String status;
	private Map<String, String> cookieContent;
	private String destination;
	
	public String getStatus() {
		return status;
	}
	public void setStatus(String status) {
		this.status = status;
	}
	public Map<String, String> getCookieContent() {
		return cookieContent;
	}
	public void setCookieContent(Map<String, String> cookieContent) {
		this.cookieContent = cookieContent;
	}
	public String getDestination() {
		return destination;
	}
	public void setDestination(String destination) {
		this.destination = destination;
	}
	
	

}
