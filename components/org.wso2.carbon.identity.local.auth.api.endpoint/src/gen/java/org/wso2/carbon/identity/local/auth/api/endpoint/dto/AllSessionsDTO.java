package org.wso2.carbon.identity.local.auth.api.endpoint.dto;

import com.fasterxml.jackson.annotation.JsonProperty;
import io.swagger.annotations.ApiModel;
import io.swagger.annotations.ApiModelProperty;

import java.util.ArrayList;
import java.util.List;





@ApiModel(description = "")
public class AllSessionsDTO  {
  
  
  
  private List<SessionDTO> sessions = new ArrayList<SessionDTO>();

  
  /**
   * Active applications in session.
   **/
  @ApiModelProperty(value = "Active applications in session.")
  @JsonProperty("sessions")
  public List<SessionDTO> getSessions() {
    return sessions;
  }
  public void setSessions(List<SessionDTO> sessions) {
    this.sessions = sessions;
  }

  

  @Override
  public String toString()  {
    StringBuilder sb = new StringBuilder();
    sb.append("class AllSessionsDTO {\n");
    
    sb.append("  sessions: ").append(sessions).append("\n");
    sb.append("}\n");
    return sb.toString();
  }
}
