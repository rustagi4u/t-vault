package com.tmobile.cso.vault.api.service;
import java.io.Console;
import java.io.IOException;
import java.util.Arrays;
import java.util.HashMap;
import java.util.List;

import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.stereotype.Component;

import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.google.common.collect.ImmutableMap;
import com.tmobile.cso.vault.api.common.TVaultConstants;
import com.tmobile.cso.vault.api.controller.ControllerUtil;
import com.tmobile.cso.vault.api.exception.LogMessage;
import com.tmobile.cso.vault.api.model.Message;
import com.tmobile.cso.vault.api.process.RequestProcessor;
import com.tmobile.cso.vault.api.process.Response;
import com.tmobile.cso.vault.api.utils.CommonUtils;
import com.tmobile.cso.vault.api.utils.JSONUtil;
import com.tmobile.cso.vault.api.utils.ThreadLocalContext;
import com.tmobile.cso.vault.api.utils.TokenUtils;

@Component
public class MessageBannerService {
	@Value("${vault.port}")
	private String vaultPort;

	@Autowired
	private RequestProcessor reqProcessor;
	@Autowired
	private TokenUtils tokenUtils;
	@Autowired
	private CommonUtils commonUtils;

	@Value("${vault.auth.method}")
	private String vaultAuthMethod;

	private static Logger log = LogManager.getLogger(MessageBannerService.class);

	public ResponseEntity<String> writeBannerMessage(String token, Message message) {
		if (!isTokenValid(token)) {
			log.error(JSONUtil.getJSON(ImmutableMap.<String, String>builder()
					.put(LogMessage.USER, ThreadLocalContext.getCurrentMap().get(LogMessage.USER))
					.put(LogMessage.ACTION, "getSecretCount")
					.put(LogMessage.MESSAGE, "Access Denied: No enough permission to access this API")
					.put(LogMessage.APIURL, ThreadLocalContext.getCurrentMap().get(LogMessage.APIURL)).build()));
			return ResponseEntity.status(HttpStatus.FORBIDDEN)
					.body("{\"errors\":[\"Access Denied: Not enough permission to access this API\"]}");
		}

		ObjectMapper objMapper = new ObjectMapper();

		HashMap<String, String> metadataMap = message.getDetails();
		
		if(metadataMap.isEmpty()) {
			return ResponseEntity.status(HttpStatus.BAD_REQUEST).body("{\"errors\":[\"Safe-message & SSL-message cannot be empty\"]}");
		}
		if((!metadataMap.containsKey("message1")) || metadataMap.containsValue("")) {
			return ResponseEntity.status(HttpStatus.BAD_REQUEST).body("{\"errors\":[\"Message cannot be empty\"]}");
		}
		else if(!metadataMap.containsKey("message2") || metadataMap.containsValue("")) {
			return ResponseEntity.status(HttpStatus.BAD_REQUEST).body("{\"errors\":[\"Message cannot be empty\"]}");
		}
		String metadataJson = "";
		try {
			metadataJson = objMapper.writeValueAsString(metadataMap);
		} catch (JsonProcessingException e) {
		}

		String path = TVaultConstants.UI_BANNER_MESSAGE_PATH;
		String writeJson = "{\"path\":\"" + path + "\",\"data\":" + metadataJson + "}";

		log.debug(JSONUtil.getJSON(ImmutableMap.<String, String>builder()
				.put(LogMessage.USER, ThreadLocalContext.getCurrentMap().get(LogMessage.USER).toString())
				.put(LogMessage.ACTION, "Write ui banner message")
				.put(LogMessage.MESSAGE, String.format("Trying to write message [%s]", path))
				.put(LogMessage.APIURL, ThreadLocalContext.getCurrentMap().get(LogMessage.APIURL).toString()).build()));

		log.debug(JSONUtil.getJSON(ImmutableMap.<String, String>builder()
				.put(LogMessage.USER, ThreadLocalContext.getCurrentMap().get(LogMessage.USER).toString())
				.put(LogMessage.ACTION, "Get Folders")
				.put(LogMessage.MESSAGE, String.format("Trying to get folders for [%s]", path))
				.put(LogMessage.APIURL, ThreadLocalContext.getCurrentMap().get(LogMessage.APIURL).toString()).build()));

		if (ControllerUtil.isFolderExisting(path, token)) {
			log.debug(JSONUtil.getJSON(ImmutableMap.<String, String>builder()
					.put(LogMessage.USER, ThreadLocalContext.getCurrentMap().get(LogMessage.USER).toString())
					.put(LogMessage.ACTION, "folder not exist")
					.put(LogMessage.MESSAGE, String.format("Trying to get folders failed [%s]", path))
					.put(LogMessage.APIURL, ThreadLocalContext.getCurrentMap().get(LogMessage.APIURL).toString())
					.build()));

			Response response = reqProcessor.process("/write", writeJson, token);
			log.debug(JSONUtil.getJSON(ImmutableMap.<String, String>builder()
					.put(LogMessage.USER, ThreadLocalContext.getCurrentMap().get(LogMessage.USER).toString())
					.put(LogMessage.ACTION, "Get Folders").put(LogMessage.MESSAGE, "Getting folders completed")
					.put(LogMessage.STATUS, response.getHttpstatus().toString())
					.put(LogMessage.APIURL, ThreadLocalContext.getCurrentMap().get(LogMessage.APIURL).toString())
					.build()));

			return ResponseEntity.status(HttpStatus.OK).body("{\"messages\":[\"Message saved to vault\"]}");
		} else {
			log.debug(JSONUtil.getJSON(ImmutableMap.<String, String>builder()
					.put(LogMessage.USER, ThreadLocalContext.getCurrentMap().get(LogMessage.USER).toString())
					.put(LogMessage.ACTION, "CreateFolder")
					.put(LogMessage.MESSAGE, String.format("Trying to Create folder [%s]", path))
					.put(LogMessage.APIURL, ThreadLocalContext.getCurrentMap().get(LogMessage.APIURL).toString())
					.build()));
			Response response = reqProcessor.process("/sdb/createfolder", writeJson, token);
			if (response.getHttpstatus().equals(HttpStatus.NO_CONTENT)) {
				log.debug(JSONUtil.getJSON(ImmutableMap.<String, String>builder()
						.put(LogMessage.USER, ThreadLocalContext.getCurrentMap().get(LogMessage.USER).toString())
						.put(LogMessage.ACTION, "Create Folder").put(LogMessage.MESSAGE, "Create Folder completed")
						.put(LogMessage.STATUS, response.getHttpstatus().toString())
						.put(LogMessage.APIURL, ThreadLocalContext.getCurrentMap().get(LogMessage.APIURL).toString())
						.build()));
				Response response1 = reqProcessor.process("/write", writeJson, token);
				log.debug(JSONUtil.getJSON(ImmutableMap.<String, String>builder()
						.put(LogMessage.USER, ThreadLocalContext.getCurrentMap().get(LogMessage.USER).toString())
						.put(LogMessage.ACTION, "Get Folders").put(LogMessage.MESSAGE, "write to folders completed")
						.put(LogMessage.STATUS, response1.getHttpstatus().toString())
						.put(LogMessage.APIURL, ThreadLocalContext.getCurrentMap().get(LogMessage.APIURL).toString())
						.build()));
				return ResponseEntity.status(HttpStatus.OK).body("{\"messages\":[\"Message saved to vault\"]}");
			}

			return ResponseEntity.status(response.getHttpstatus()).body(response.getResponse());
		}
	}

	public ResponseEntity<String> readBannerMessage() {
		String token = tokenUtils.getSelfServiceToken();

		String path = TVaultConstants.UI_BANNER_MESSAGE_PATH;

		log.debug(JSONUtil.getJSON(ImmutableMap.<String, String>builder()
				.put(LogMessage.USER, ThreadLocalContext.getCurrentMap().get(LogMessage.USER).toString())
				.put(LogMessage.ACTION, "Get Info")
				.put(LogMessage.MESSAGE, String.format("Trying to get Info for [%s]", path))
				.put(LogMessage.APIURL, ThreadLocalContext.getCurrentMap().get(LogMessage.APIURL).toString()).build()));
		Response response = reqProcessor.process("/sdb", "{\"path\":\"" + path + "\"}", token);
		log.debug(JSONUtil.getJSON(ImmutableMap.<String, String>builder()
				.put(LogMessage.USER, ThreadLocalContext.getCurrentMap().get(LogMessage.USER).toString())
				.put(LogMessage.ACTION, "Get Info").put(LogMessage.MESSAGE, "Getting Info completed")
				.put(LogMessage.STATUS, response.getHttpstatus().toString())
				.put(LogMessage.APIURL, ThreadLocalContext.getCurrentMap().get(LogMessage.APIURL).toString()).build()));
		return ResponseEntity.status(response.getHttpstatus()).body(response.getResponse());

	}
	
	public ResponseEntity<String> updateBannerMessage(String token, Message message){
		
		if (!isTokenValid(token)) {
			log.error(JSONUtil.getJSON(ImmutableMap.<String, String>builder()
					.put(LogMessage.USER, ThreadLocalContext.getCurrentMap().get(LogMessage.USER))
					.put(LogMessage.ACTION, "getSecretCount")
					.put(LogMessage.MESSAGE, "Access Denied: No enough permission to access this API")
					.put(LogMessage.APIURL, ThreadLocalContext.getCurrentMap().get(LogMessage.APIURL)).build()));
			return ResponseEntity.status(HttpStatus.FORBIDDEN)
					.body("{\"errors\":[\"Access Denied: No enough permission to access this API\"]}");
		}
		ObjectMapper objMapper = new ObjectMapper();

		HashMap<String, String> metadataMap = message.getDetails();
		
		if(metadataMap.isEmpty()) {
			return ResponseEntity.status(HttpStatus.BAD_REQUEST).body("{\"errors\":[\"Safe-message & SSL-message cannot be empty\"]}");
		}
		if((!metadataMap.containsKey("message1")) || metadataMap.containsValue("")) {
			return ResponseEntity.status(HttpStatus.BAD_REQUEST).body("{\"errors\":[\"Message cannot be empty\"]}");
		}
		else if(!metadataMap.containsKey("message2") || metadataMap.containsValue("")) {
			return ResponseEntity.status(HttpStatus.BAD_REQUEST).body("{\"errors\":[\"Message cannot be empty\"]}");
		}
		
		String metadataJson = "";
		try {
			metadataJson = objMapper.writeValueAsString(metadataMap);
		} catch (JsonProcessingException e) {
		}

		String path = TVaultConstants.UI_BANNER_MESSAGE_PATH;
		String writeJson = "{\"path\":\"" + path + "\",\"data\":" + metadataJson + "}";

		log.debug(JSONUtil.getJSON(ImmutableMap.<String, String>builder()
				.put(LogMessage.USER, ThreadLocalContext.getCurrentMap().get(LogMessage.USER).toString())
				.put(LogMessage.ACTION, "Write message")
				.put(LogMessage.MESSAGE, String.format("Trying to write message [%s]", path))
				.put(LogMessage.APIURL, ThreadLocalContext.getCurrentMap().get(LogMessage.APIURL).toString()).build()));

		log.debug(JSONUtil.getJSON(ImmutableMap.<String, String>builder()
				.put(LogMessage.USER, ThreadLocalContext.getCurrentMap().get(LogMessage.USER).toString())
				.put(LogMessage.ACTION, "Get Folders")
				.put(LogMessage.MESSAGE, String.format("Trying to get folders for [%s]", path))
				.put(LogMessage.APIURL, ThreadLocalContext.getCurrentMap().get(LogMessage.APIURL).toString()).build()));

		if (ControllerUtil.isFolderExisting(path, token)) {
			log.debug(JSONUtil.getJSON(ImmutableMap.<String, String>builder()
					.put(LogMessage.USER, ThreadLocalContext.getCurrentMap().get(LogMessage.USER).toString())
					.put(LogMessage.ACTION, "folder not exist")
					.put(LogMessage.MESSAGE, String.format("Trying to get folders failed [%s]", path))
					.put(LogMessage.APIURL, ThreadLocalContext.getCurrentMap().get(LogMessage.APIURL).toString())
					.build()));

			Response response = reqProcessor.process("/write", writeJson, token);
			log.debug(JSONUtil.getJSON(ImmutableMap.<String, String>builder()
					.put(LogMessage.USER, ThreadLocalContext.getCurrentMap().get(LogMessage.USER).toString())
					.put(LogMessage.ACTION, "Get Folders").put(LogMessage.MESSAGE, "Getting folders completed")
					.put(LogMessage.STATUS, response.getHttpstatus().toString())
					.put(LogMessage.APIURL, ThreadLocalContext.getCurrentMap().get(LogMessage.APIURL).toString())
					.build()));

			return ResponseEntity.status(HttpStatus.OK).body("{\"messages\":[\"Updated message saved to vault\"]}");
		} else {
			log.debug(JSONUtil.getJSON(ImmutableMap.<String, String>builder()
					.put(LogMessage.USER, ThreadLocalContext.getCurrentMap().get(LogMessage.USER).toString())
					.put(LogMessage.ACTION, "CreateFolder")
					.put(LogMessage.MESSAGE, String.format("Trying to Create folder [%s]", path))
					.put(LogMessage.APIURL, ThreadLocalContext.getCurrentMap().get(LogMessage.APIURL).toString())
					.build()));
			Response response = reqProcessor.process("/sdb/createfolder", writeJson, token);
			if (response.getHttpstatus().equals(HttpStatus.NO_CONTENT)) {
				log.debug(JSONUtil.getJSON(ImmutableMap.<String, String>builder()
						.put(LogMessage.USER, ThreadLocalContext.getCurrentMap().get(LogMessage.USER).toString())
						.put(LogMessage.ACTION, "Create Folder").put(LogMessage.MESSAGE, "Create Folder completed")
						.put(LogMessage.STATUS, response.getHttpstatus().toString())
						.put(LogMessage.APIURL, ThreadLocalContext.getCurrentMap().get(LogMessage.APIURL).toString())
						.build()));
				Response response1 = reqProcessor.process("/write", writeJson, token);
				log.debug(JSONUtil.getJSON(ImmutableMap.<String, String>builder()
						.put(LogMessage.USER, ThreadLocalContext.getCurrentMap().get(LogMessage.USER).toString())
						.put(LogMessage.ACTION, "Get Folders").put(LogMessage.MESSAGE, "write to folders completed")
						.put(LogMessage.STATUS, response1.getHttpstatus().toString())
						.put(LogMessage.APIURL, ThreadLocalContext.getCurrentMap().get(LogMessage.APIURL).toString())
						.build()));
				return ResponseEntity.status(HttpStatus.OK).body("{\"messages\":[\"Updated message saved to vault\"]}");
			}
		return ResponseEntity.status(response.getHttpstatus()).body(response.getResponse());
		}
	}

	private boolean isTokenValid(String token) {
		ObjectMapper objectMapper = new ObjectMapper();
		List<String> currentPolicies;
		Response response = reqProcessor.process("/auth/tvault/lookup", "{}", token);
		if (HttpStatus.OK.equals(response.getHttpstatus())) {
			String responseJson = response.getResponse();
			try {
				currentPolicies = Arrays.asList(commonUtils.getPoliciesAsArray(objectMapper, responseJson));
				if (currentPolicies.contains(TVaultConstants.WRITE_MESSAGE_POLICY)) {
					log.debug(JSONUtil.getJSON(ImmutableMap.<String, String>builder()
							.put(LogMessage.USER, ThreadLocalContext.getCurrentMap().get(LogMessage.USER))
							.put(LogMessage.ACTION, "isAuthorizedToGetSecretCount")
							.put(LogMessage.MESSAGE, "The Token has required policies to get total secret count.")
							.put(LogMessage.APIURL, ThreadLocalContext.getCurrentMap().get(LogMessage.APIURL))
							.build()));
					return true;
				}
			} catch (IOException e) {
				log.error(JSONUtil.getJSON(ImmutableMap.<String, String>builder()
						.put(LogMessage.USER, ThreadLocalContext.getCurrentMap().get(LogMessage.USER))
						.put(LogMessage.ACTION, "isAuthorizedToGetSecretCount")
						.put(LogMessage.MESSAGE, "Failed to parse policies from token")
						.put(LogMessage.APIURL, ThreadLocalContext.getCurrentMap().get(LogMessage.APIURL)).build()));
			}
		}
		log.debug(JSONUtil.getJSON(ImmutableMap.<String, String>builder()
				.put(LogMessage.USER, ThreadLocalContext.getCurrentMap().get(LogMessage.USER))
				.put(LogMessage.ACTION, "isAuthorizedToGetSecretCount")
				.put(LogMessage.MESSAGE, "The Token does not have required policies to get total secret count.")
				.put(LogMessage.APIURL, ThreadLocalContext.getCurrentMap().get(LogMessage.APIURL)).build()));
		return false;
	}
}
