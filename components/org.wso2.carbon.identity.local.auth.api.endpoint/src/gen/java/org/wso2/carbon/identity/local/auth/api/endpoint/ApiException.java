package org.wso2.carbon.identity.local.auth.api.endpoint;
//comment
public class ApiException extends Exception{
	private int code;
	public ApiException (int code, String msg) {
		super(msg);
		this.code = code;
	}
}
