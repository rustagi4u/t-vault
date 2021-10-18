package com.tmobile.cso.vault.api.model;
import java.io.Serializable;
import java.util.HashMap;

import com.fasterxml.jackson.annotation.JsonProperty;

import io.swagger.annotations.ApiModelProperty;
public class Message {

	private static final long serialVersionUID = 5801186298788991628L;

	@JsonProperty("data") private HashMap<String, String> details;


	public Message() {
		super();
		// TODO Auto-generated constructor stub
	}


	public Message(HashMap<String, String> details) {
		super();
		this.details = details;
	}

	//@ApiModelProperty(example="{\n" + "     \"message1\":\"value1\",\r\n" +
	//		  "    \"message2\":\"value2\"\n" + "  }", position=2, required=true)

	  @ApiModelProperty(example="{\r\n" +
	            "     \"message1\":\"value1\",\r\n" +
	            "    \"message2\":\"value2\"\r\n" +
	            "  }", position=2, required=true)
	public HashMap<String, String> getDetails() {
		return details;
	}


	public void setDetails(HashMap<String, String> details) {
		this.details = details;
	}
}
