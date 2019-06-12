package org.wso2.carbon.identity.local.auth.api.endpoint.dto;


import com.fasterxml.jackson.annotation.JsonProperty;
import io.swagger.annotations.ApiModel;
import io.swagger.annotations.ApiModelProperty;





@ApiModel(description = "")
public class ApplicationDTO  {
  
  
  
  private String subject = null;
  
  
  private String app = null;

  
  /**
   * User name of application.
   **/
  @ApiModelProperty(value = "User name of application.")
  @JsonProperty("subject")
  public String getSubject() {
    return subject;
  }
  public void setSubject(String subject) {
    this.subject = subject;
  }

  
  /**
   * Name of application.
   **/
  @ApiModelProperty(value = "Name of application.")
  @JsonProperty("app")
  public String getApp() {
    return app;
  }
  public void setApp(String app) {
    this.app = app;
  }

  

  @Override
  public String toString()  {
    StringBuilder sb = new StringBuilder();
    sb.append("class ApplicationDTO {\n");
    
    sb.append("  subject: ").append(subject).append("\n");
    sb.append("  app: ").append(app).append("\n");
    sb.append("}\n");
    return sb.toString();
  }
}
