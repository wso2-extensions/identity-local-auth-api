package org.wso2.carbon.identity.local.auth.api.endpoint.dto;


import io.swagger.annotations.*;
import com.fasterxml.jackson.annotation.*;

import javax.validation.constraints.NotNull;





@ApiModel(description = "")
@JsonIgnoreProperties
public class AuthenticationRequestDTO  {
  
  
  
  private String username = null;

  private String password = null;

  private  String sessionDataKey = null;

  
  /**
   **/
  @ApiModelProperty(value = "")
  @JsonProperty("username")
  public String getUsername() {
    return username;
  }
  public void setUsername(String username) {
    this.username = username;
  }

  
  /**
   **/
  @ApiModelProperty(value = "")
  @JsonProperty("password")
  public String getPassword() {
    return password;
  }
  public void setPassword(String password) {
    this.password = password;
  }

  /**
   **/
  @ApiModelProperty(value = "")
  @JsonProperty("sessionDataKey")
  public String getSessionDataKey() {
    return sessionDataKey;
  }
  public void setSessionDataKey(String sessionDataKey) {
    this.sessionDataKey = sessionDataKey;
  }

  

  @Override
  public String toString()  {
    StringBuilder sb = new StringBuilder();
    sb.append("class AuthenticationRequestDTO {\n");
    
    sb.append("  username: ").append(username).append("\n");
    sb.append("  password: ").append(password).append("\n");
    sb.append("  sessionDataKey: ").append(sessionDataKey).append("\n");
    sb.append("}\n");
    return sb.toString();
  }
}
