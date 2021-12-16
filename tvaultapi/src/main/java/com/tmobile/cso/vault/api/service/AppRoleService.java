// =========================================================================
// Copyright 2020 T-Mobile, US
//
// Licensed under the Apache License, Version 2.0 (the "License")
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//    http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.
// See the readme.txt file for additional language around disclaimer of warranties.
// =========================================================================

package com.tmobile.cso.vault.api.service;

import java.io.IOException;
import java.util.*;

import com.fasterxml.jackson.core.JsonProcessingException;
import com.tmobile.cso.vault.api.model.*;
import com.tmobile.cso.vault.api.utils.CommonUtils;
import com.tmobile.cso.vault.api.utils.EmailUtils;
import org.apache.commons.collections.CollectionUtils;
import org.apache.commons.lang3.StringUtils;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.stereotype.Component;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.google.common.collect.ImmutableMap;
import com.tmobile.cso.vault.api.common.AzureServiceAccountConstants;
import com.tmobile.cso.vault.api.common.IAMServiceAccountConstants;
import com.tmobile.cso.vault.api.common.SSLCertificateConstants;
import com.tmobile.cso.vault.api.common.TVaultConstants;
import com.tmobile.cso.vault.api.controller.ControllerUtil;
import com.tmobile.cso.vault.api.exception.LogMessage;
import com.tmobile.cso.vault.api.process.RequestProcessor;
import com.tmobile.cso.vault.api.process.Response;
import com.tmobile.cso.vault.api.utils.JSONUtil;
import com.tmobile.cso.vault.api.utils.ThreadLocalContext;

@Component
public class  AppRoleService {

	@Value("${vault.port}")
	private String vaultPort;
	
	@Autowired
	private RequestProcessor reqProcessor;

	@Value("${vault.auth.method}")
	private String vaultAuthMethod;

	@Value("${ad.notification.fromemail}")
	private String supportEmail;

	@Autowired
	private EmailUtils emailUtils;

	@Autowired
	private CommonUtils commonUtils;

	private static Logger log = LogManager.getLogger(AppRoleService.class);
	
	private static final String POLICIESSTR = "policies";
	private static final String CREATEPATH = "/auth/approle/role/create";
	private static final String READPATH = "/auth/approle/role/read";
	private static final String ROLENAMESTR = "{\"role_name\":\"";
	private static final String READCOMPLETESTR = "Reading AppRole completed";
	private static final String APPROLENONEXISTSTR = "{\"errors\":[\"AppRole doesn't exist\"]}";
	private static final String PATHSTR = "{\"path\":\"";
	private static final String READPOLEIDPATH = "/auth/approle/role/readRoleID";
	private static final String READROLEID = "readRoleId";
	private static final String READROLEFAILMSG = "Reading role_id for AppRole failed";
	private static final String READACCESSCOMPLETEMSG = "Reading accessors of all the SecretIDs for AppRole completed";
	private static final String READAPPROLESECRETID = "readAppRoleSecretId";
	private static final String READAPPROLEROLEID = "readAppRoleRoleId";
	private static final String SECRETIDACCESSORS = "readSecretIdAccessors";
	private static final String ACCESS = "access";
	private static final String DELETESECRET = "deleteSecretIds";
	private static final String ASSOCIATEAPPROLE = "Associate AppRole to SDB";
	private static final String CREATE_APPROLE = "Create Approle";
	private static final String UPDATE_APPROLE ="Update AppRole";
	private static final String DELETE_APPROLE ="Delete AppRole";
	private static final String READ_APPROLE ="Read AppRole";
	private static final String READ_APPROLE_ID ="Read AppRoleId";
	
	/**
	 * Create AppRole
	 * @param token
	 * @param appRole
	 * @param userDetails
	 * @return ResponseEntity<String>
	 */
	public ResponseEntity<String> createAppRole(String token, AppRole appRole, UserDetails userDetails){
		String jsonStr = JSONUtil.getJSON(appRole);
		log.debug(JSONUtil.getJSON(ImmutableMap.<String, String>builder().
			      put(LogMessage.USER, ThreadLocalContext.getCurrentMap().get(LogMessage.USER)).
				  put(LogMessage.ACTION, CREATE_APPROLE).
			      put(LogMessage.MESSAGE, String.format("Start trying to create AppRole [%s].", appRole.getRole_name())).
			      put(LogMessage.APIURL, ThreadLocalContext.getCurrentMap().get(LogMessage.APIURL)).
			      build()));
		if (!ControllerUtil.areAppRoleInputsValid(appRole)) {
			log.error(JSONUtil.getJSON(ImmutableMap.<String, String>builder().
				      put(LogMessage.USER, ThreadLocalContext.getCurrentMap().get(LogMessage.USER)).
					  put(LogMessage.ACTION, CREATE_APPROLE).
				      put(LogMessage.MESSAGE, "Invalid input parameters").
				      put(LogMessage.APIURL, ThreadLocalContext.getCurrentMap().get(LogMessage.APIURL)).
				      build()));
			return ResponseEntity.status(HttpStatus.BAD_REQUEST).body("{\"errors\":[\"Invalid input values for AppRole creation\"]}");
		}
		
		if (Arrays.asList(TVaultConstants.SELF_SUPPORT_ADMIN_APPROLES).contains(appRole.getRole_name())) {
			return ResponseEntity.status(HttpStatus.BAD_REQUEST)
					.body("{\"errors\":[\"Access denied: no permission to create an approle named "
							+ appRole.getRole_name() + "\"]}");
		}
		jsonStr = ControllerUtil.convertAppRoleInputsToLowerCase(jsonStr);
		boolean isDuplicate = isAppRoleDuplicate(appRole.getRole_name().toLowerCase(), token);

		if (!CollectionUtils.isEmpty(appRole.getShared_to())) {
			AppRoleMetadataDetails appRoleMetadataDetails = new AppRoleMetadataDetails();
			appRoleMetadataDetails.setCreatedBy(userDetails.getUsername());
			if (!validateNoSharedUserIsOwner(appRoleMetadataDetails, appRole.getShared_to())) {
				return ResponseEntity.status(HttpStatus.INTERNAL_SERVER_ERROR)
						.body("{\"errors\":[\"An AppRole cannot be shared with the current owner\"]}");
			}
		}

		if (!isDuplicate) {
			Response response = reqProcessor.process(CREATEPATH, jsonStr,token);
			if (response.getHttpstatus().equals(HttpStatus.NO_CONTENT) || response.getHttpstatus().equals(HttpStatus.OK)) {
				boolean metadataCreatedSuccessfully = createAppRoleMetaData(token, appRole, userDetails.getUsername());
				if(metadataCreatedSuccessfully) {
					log.debug(JSONUtil.getJSON(ImmutableMap.<String, String>builder().
							put(LogMessage.USER, ThreadLocalContext.getCurrentMap().get(LogMessage.USER)).
							put(LogMessage.ACTION, CREATE_APPROLE).
							put(LogMessage.MESSAGE, String.format ("Approle [%s] Created Successfully by [%s]",appRole.getRole_name(),userDetails.getUsername())).
							put(LogMessage.STATUS, response.getHttpstatus().toString()).
							put(LogMessage.APIURL, ThreadLocalContext.getCurrentMap().get(LogMessage.APIURL)).
							build()));
					return ResponseEntity.status(HttpStatus.OK).body("{\"messages\":[\"AppRole created successfully\"]}");
				}
				// revert approle creation
				Response deleteResponse = reqProcessor.process("/auth/approle/role/delete",jsonStr,token);
				if (deleteResponse.getHttpstatus().equals(HttpStatus.NO_CONTENT)) {
					return ResponseEntity.status(HttpStatus.INTERNAL_SERVER_ERROR).body("{\"errors\":[\"AppRole creation failed.\"]}");
				}
				else {
					return ResponseEntity.status(HttpStatus.OK).body("{\"messages\":[\"AppRole created however metadata update failed. Please try with AppRole/update \"]}");
				}
			}
			log.error(JSONUtil.getJSON(ImmutableMap.<String, String>builder().
				      put(LogMessage.USER, ThreadLocalContext.getCurrentMap().get(LogMessage.USER)).
					  put(LogMessage.ACTION, CREATE_APPROLE).
				      put(LogMessage.MESSAGE, "Creation of AppRole failed").
				      put(LogMessage.RESPONSE, response.getResponse()).
				      put(LogMessage.STATUS, response.getHttpstatus().toString()).
				      put(LogMessage.APIURL, ThreadLocalContext.getCurrentMap().get(LogMessage.APIURL)).
				      build()));
			return ResponseEntity.status(response.getHttpstatus()).body(response.getResponse());
		}
		else {
			return ResponseEntity.status(HttpStatus.BAD_REQUEST).body("{\"errors\":[\"AppRole already exists and can't be created\"]}");
		}
	
	}

	/**
	 * Creates metadata for app role in the following order - <br><br>
	 * 1. General AppRole metadata in path metadata/approle<br>
	 * 2. User metadata in path metadata/approle_users (for quick search of AppRoles for user)<br>
	 * 3. Metadata for sharedTo users (if any exist), who will have access to read and delete keys.<br>
	 * @param token
	 * @param userDetails
	 * @param appRole
	 * @return boolean
	 */
	private boolean createAppRoleMetaData(String token, AppRole appRole, String username) {
		String metadataJson = ControllerUtil.populateAppRoleMetaJson(appRole, username);
		boolean appRoleMetaDataCreationStatus = ControllerUtil.createMetadata(metadataJson, token);
		String appRoleUsermetadataJson = ControllerUtil.populateUserMetaJson(appRole, username);
		boolean appRoleUserMetaDataCreationStatus = ControllerUtil.createMetadata(appRoleUsermetadataJson, token);
		boolean appRoleSharedToUserMetaDataCreationStatus = true;
		if (appRole.getShared_to() != null) {
			for (String sharedToUser : appRole.getShared_to()) {
				if (StringUtils.isNotEmpty(sharedToUser)) {
					String appRoleSharedToMetadataJson = ControllerUtil.populateSharedToUserMetaJson(username, sharedToUser, appRole);
					appRoleSharedToUserMetaDataCreationStatus = ControllerUtil.createMetadata(appRoleSharedToMetadataJson, token);
				}
			}
		}
		return appRoleMetaDataCreationStatus && appRoleUserMetaDataCreationStatus && appRoleSharedToUserMetaDataCreationStatus;
	}

	/**
	 * Checks for duplicated AppRole
	 * @param appRoleName
	 * @param token
	 * @return boolean
	 */
	private boolean isAppRoleDuplicate(String appRoleName, String token) {
		log.debug(JSONUtil.getJSON(ImmutableMap.<String, String>builder().
			      put(LogMessage.USER, ThreadLocalContext.getCurrentMap().get(LogMessage.USER)).
				  put(LogMessage.ACTION, "isAppRoleDuplicate").
			      put(LogMessage.MESSAGE,"Checks for duplicated AppRole.").
			      put(LogMessage.APIURL, ThreadLocalContext.getCurrentMap().get(LogMessage.APIURL)).
			      build()));
		boolean isDuplicate = false;
		ResponseEntity<String> appRolesListResponseEntity = readAppRoles(token);
		String appRolesListRes = appRolesListResponseEntity.getBody();
		Map<String,Object> appRolesList = ControllerUtil.parseJson(appRolesListRes);
		ArrayList<String> existingAppRoles = (ArrayList<String>) appRolesList.get("keys");
		if (!CollectionUtils.isEmpty(existingAppRoles)) {
			for (String existingAppRole: existingAppRoles) {
				if (existingAppRole.equalsIgnoreCase(appRoleName)) {
					isDuplicate = true;
					break;
				}
			}
		}
		log.debug(JSONUtil.getJSON(ImmutableMap.<String, String>builder().
			      put(LogMessage.USER, ThreadLocalContext.getCurrentMap().get(LogMessage.USER)).
				  put(LogMessage.ACTION, "isAppRoleDuplicate").
			      put(LogMessage.MESSAGE,"Completed checks for duplicated AppRole.").
			      put(LogMessage.APIURL, ThreadLocalContext.getCurrentMap().get(LogMessage.APIURL)).
			      build()));
		return isDuplicate;
	}
	/**
	 * Reads approle information
	 * @param token
	 * @param rolename
	 * @return ResponseEntity<String>
	 */
	public ResponseEntity<String> readAppRole(String token, String rolename){

		if (TVaultConstants.HIDESELFSUPPORTADMINAPPROLE && Arrays.asList(TVaultConstants.SELF_SUPPORT_ADMIN_APPROLES).contains(rolename)) {
			return ResponseEntity.status(HttpStatus.BAD_REQUEST).body("{\"errors\":[\"Access denied: no permission to read this AppRole\"]}");
		}
		log.debug(JSONUtil.getJSON(ImmutableMap.<String, String>builder().
			      put(LogMessage.USER, ThreadLocalContext.getCurrentMap().get(LogMessage.USER)).
				  put(LogMessage.ACTION, READ_APPROLE).
			      put(LogMessage.MESSAGE, String.format("Start trying to read AppRole [%s].", rolename)).
			      put(LogMessage.APIURL, ThreadLocalContext.getCurrentMap().get(LogMessage.APIURL)).
			      build()));
		Response response = reqProcessor.process(READPATH,ROLENAMESTR+rolename+"\"}",token);
		if(HttpStatus.OK.equals(response.getHttpstatus())) {
			log.debug(JSONUtil.getJSON(ImmutableMap.<String, String>builder().
				      put(LogMessage.USER, ThreadLocalContext.getCurrentMap().get(LogMessage.USER)).
					  put(LogMessage.ACTION, READ_APPROLE).
				      put(LogMessage.MESSAGE, READCOMPLETESTR).
				      put(LogMessage.STATUS, response.getHttpstatus().toString()).
				      put(LogMessage.APIURL, ThreadLocalContext.getCurrentMap().get(LogMessage.APIURL)).
				      build()));

			populateResponseWithSharedTo(token, rolename, response);

			return ResponseEntity.status(response.getHttpstatus()).body(response.getResponse());
		}
		else if (HttpStatus.NOT_FOUND.equals(response.getHttpstatus())) {
			log.debug(JSONUtil.getJSON(ImmutableMap.<String, String>builder().
				      put(LogMessage.USER, ThreadLocalContext.getCurrentMap().get(LogMessage.USER)).
					  put(LogMessage.ACTION, READ_APPROLE).
				      put(LogMessage.MESSAGE, READCOMPLETESTR).
				      put(LogMessage.STATUS, response.getHttpstatus().toString()).
				      put(LogMessage.APIURL, ThreadLocalContext.getCurrentMap().get(LogMessage.APIURL)).
				      build()));
			return ResponseEntity.status(HttpStatus.OK).body(APPROLENONEXISTSTR);
		}
		else {
			log.error(JSONUtil.getJSON(ImmutableMap.<String, String>builder().
				      put(LogMessage.USER, ThreadLocalContext.getCurrentMap().get(LogMessage.USER)).
					  put(LogMessage.ACTION,READ_APPROLE ).
				      put(LogMessage.MESSAGE, READCOMPLETESTR).
				      put(LogMessage.STATUS, response.getHttpstatus().toString()).
				      put(LogMessage.APIURL, ThreadLocalContext.getCurrentMap().get(LogMessage.APIURL)).
				      build()));
			return ResponseEntity.status(response.getHttpstatus()).body(response.getResponse());
		}
	}

	/**
	 * Populates response with sharedTo users so they can be displayed when the AppRole is read
	 * @param token
	 * @param roleName
	 * @param response
	 * @return void
	 */
	private void populateResponseWithSharedTo(String token, String roleName, Response response) {
		AppRoleMetadata appRoleMetadata = readAppRoleMetadata(token, roleName);
		List<String> sharedTo = null;
		if (appRoleMetadata != null) {
			sharedTo = appRoleMetadata.getAppRoleMetadataDetails().getSharedTo();
		} else {
			log.error(JSONUtil.getJSON(ImmutableMap.<String, String>builder().
				put(LogMessage.USER, ThreadLocalContext.getCurrentMap().get(LogMessage.USER)).
				put(LogMessage.ACTION, "populateResponseWithSharedTo").
				put(LogMessage.MESSAGE, "Failed to populate response with sharedTo users because unable fetch metadata.").
				put(LogMessage.APIURL, ThreadLocalContext.getCurrentMap().get(LogMessage.APIURL)).
				build()));
		}

		if (!CollectionUtils.isEmpty(sharedTo)) {
			StringBuilder newResponse = new StringBuilder(response.getResponse().replace("}}", ",\"shared_to\":["));
			for (String sharedToUser : sharedTo) {
				newResponse.append("\"").append(sharedToUser).append("\",");
			}
			newResponse = new StringBuilder(newResponse.substring(0, newResponse.length() - 1) + "]}}");
			response.setResponse(newResponse.toString());
		}
	}

	/**
	 * Reads the list of AppRoles
	 * @param token
	 * @return ResponseEntity<String>
	 */
	public ResponseEntity<String> readAppRoles(String token) {
		Integer offset = null;
		Integer limit = null;
		log.debug(JSONUtil.getJSON(ImmutableMap.<String, String>builder().
			      put(LogMessage.USER, ThreadLocalContext.getCurrentMap().get(LogMessage.USER)).
				  put(LogMessage.ACTION, "readAppRoles").
			      put(LogMessage.MESSAGE, "Trying to get list of AppRole").
			      put(LogMessage.APIURL, ThreadLocalContext.getCurrentMap().get(LogMessage.APIURL)).
			      build()));
		Response response = reqProcessor.process("/auth/approle/role/list","{}",token);
		log.debug(JSONUtil.getJSON(ImmutableMap.<String, String>builder().
			      put(LogMessage.USER, ThreadLocalContext.getCurrentMap().get(LogMessage.USER)).
				  put(LogMessage.ACTION, "readAppRoles").
			      put(LogMessage.MESSAGE, "Reading List of AppRoles completed").
			      put(LogMessage.STATUS, response.getHttpstatus().toString()).
			      put(LogMessage.APIURL, ThreadLocalContext.getCurrentMap().get(LogMessage.APIURL)).
			      build()));
		if (HttpStatus.OK.equals(response.getHttpstatus()) && TVaultConstants.HIDESELFSUPPORTADMINAPPROLE) {
			response = ControllerUtil.hideSelfSupportAdminAppRoleFromResponse(response, limit, offset);
		}
		return ResponseEntity.status(response.getHttpstatus()).body(response.getResponse());
	}
	/**
	 * Reads the list of AppRoles
	 * @param token
	 * @param userDetails
	 * @param limit
	 * @param offset
	 * @return ResponseEntity
	 */
	public ResponseEntity<List<AppRoleListObject>> listAppRoles(String token,  UserDetails userDetails, Integer limit, Integer offset) {
		log.debug(JSONUtil.getJSON(ImmutableMap.<String, String>builder().
			      put(LogMessage.USER, ThreadLocalContext.getCurrentMap().get(LogMessage.USER)).
				  put(LogMessage.ACTION, "listAppRoles").
			      put(LogMessage.MESSAGE, "Trying to get list of AppRole").
			      put(LogMessage.APIURL, ThreadLocalContext.getCurrentMap().get(LogMessage.APIURL)).
			      build()));
		String path = TVaultConstants.APPROLE_USERS_METADATA_MOUNT_PATH + "/" + userDetails.getUsername();
		Response response = null;
		if (userDetails.isAdmin()) {
			response = reqProcessor.process("/auth/approle/role/list",PATHSTR+ path +"\"}",token);
		}
		else {
			response = reqProcessor.process("/auth/approles/rolesbyuser/list",PATHSTR+ path +"\"}",userDetails.getSelfSupportToken());
		}

		log.debug(JSONUtil.getJSON(ImmutableMap.<String, String>builder().
			      put(LogMessage.USER, ThreadLocalContext.getCurrentMap().get(LogMessage.USER)).
				  put(LogMessage.ACTION, "listAppRoles").
			      put(LogMessage.MESSAGE, "Reading List of AppRoles completed").
			      put(LogMessage.STATUS, response.getHttpstatus().toString()).
			      put(LogMessage.APIURL, ThreadLocalContext.getCurrentMap().get(LogMessage.APIURL)).
			      build()));
		if (HttpStatus.OK.equals(response.getHttpstatus())) {
			List<AppRoleListObject> listObjects = getAppRoleObjectList(userDetails, token, response);

			if (TVaultConstants.HIDESELFSUPPORTADMINAPPROLE) {
				response = ControllerUtil.hideSelfSupportAdminAppRoleFromResponse(response, limit, offset);
			}
			return ResponseEntity.status(response.getHttpstatus()).body(listObjects);
		}
		else if (HttpStatus.NOT_FOUND.equals(response.getHttpstatus())) {
			return ResponseEntity.status(HttpStatus.OK).body(new ArrayList<>());
		}
		return ResponseEntity.status(response.getHttpstatus()).body(new ArrayList<>());
	}

	/**
	 * Gets list of AppRoleListObjects
	 * @param token
	 * @param response
	 * @return List
	 */
	private List<AppRoleListObject> getAppRoleObjectList(UserDetails userDetails, String token, Response response) {
		Map<String, Object> responseMap = ControllerUtil.parseJson(response.getResponse());
		if(responseMap.isEmpty()) {
			log.error(JSONUtil.getJSON(ImmutableMap.<String, String>builder().
					put(LogMessage.USER, ThreadLocalContext.getCurrentMap().get(LogMessage.USER)).
					put(LogMessage.ACTION, "listAppRoles").
					put(LogMessage.MESSAGE, "Failed to read JSON AppRole list.").
					put(LogMessage.APIURL, ThreadLocalContext.getCurrentMap().get(LogMessage.APIURL)).
					build()));
		}

		List<String> appRoleNames = (ArrayList<String>) responseMap.get("keys");
		List<AppRoleListObject> listObjects = new ArrayList<>();
		if (appRoleNames != null && !appRoleNames.isEmpty()) {
			for (String roleName : appRoleNames) {
				AppRoleMetadata appRoleMetadata = readAppRoleMetadata(token, roleName);
				AppRoleMetadataDetails appRoleMetadataDetails = null;
				if (appRoleMetadata != null) {
					appRoleMetadataDetails = appRoleMetadata.getAppRoleMetadataDetails();
				} else {
					log.error(JSONUtil.getJSON(ImmutableMap.<String, String>builder().
							put(LogMessage.USER, ThreadLocalContext.getCurrentMap().get(LogMessage.USER)).
							put(LogMessage.ACTION, "listAppRoles").
							put(LogMessage.MESSAGE, "Failed to get AppRole metadata.").
							put(LogMessage.APIURL, ThreadLocalContext.getCurrentMap().get(LogMessage.APIURL)).
							build()));
					continue;
				}
				boolean isOwner = false;
				if (appRoleMetadataDetails != null) {
					isOwner = isAppRoleOwner(userDetails.getUsername(), appRoleMetadataDetails);
				}
				listObjects.add(new AppRoleListObject(roleName, isOwner));
			}
		}
		return listObjects;
	}

	/**
	 * Gets roleid for approle
	 * @param token
	 * @param rolename
	 * @return ResponseEntity<String>
	 */
	public ResponseEntity<String> readAppRoleRoleId(String token, String rolename){
		log.debug(JSONUtil.getJSON(ImmutableMap.<String, String>builder().
			      put(LogMessage.USER, ThreadLocalContext.getCurrentMap().get(LogMessage.USER)).
				  put(LogMessage.ACTION,READ_APPROLE_ID ).
			      put(LogMessage.MESSAGE, String.format("Trying to read AppRoleId for the role [%s].", rolename)).
			      put(LogMessage.APIURL, ThreadLocalContext.getCurrentMap().get(LogMessage.APIURL)).
			      build()));
		if (Arrays.asList(TVaultConstants.SELF_SUPPORT_ADMIN_APPROLES).contains(rolename)) {
			return ResponseEntity.status(HttpStatus.BAD_REQUEST).body("{\"errors\":[\"Access denied: no permission to read roleID of this AppRole\"]}");
		}
		Response response = reqProcessor.process(READPOLEIDPATH,ROLENAMESTR+rolename+"\"}",token);
		log.debug(JSONUtil.getJSON(ImmutableMap.<String, String>builder().
			      put(LogMessage.USER, ThreadLocalContext.getCurrentMap().get(LogMessage.USER)).
				  put(LogMessage.ACTION, READ_APPROLE_ID).
			      put(LogMessage.MESSAGE, "Reading AppRoleId Completed").
			      put(LogMessage.STATUS, response.getHttpstatus().toString()).
			      put(LogMessage.APIURL, ThreadLocalContext.getCurrentMap().get(LogMessage.APIURL)).
			      build()));
		return ResponseEntity.status(response.getHttpstatus()).body(response.getResponse());	
	}
	/**
	 * Gets roleid for approle
	 * @param token
	 * @param rolename
	 * @return String
	 */
	public String readRoleId(String token, String rolename){
		String roleId = null;
		if (Arrays.asList(TVaultConstants.SELF_SUPPORT_ADMIN_APPROLES).contains(rolename)) {
			log.error(JSONUtil.getJSON(ImmutableMap.<String, String> builder()
					.put(LogMessage.USER, ThreadLocalContext.getCurrentMap().get(LogMessage.USER))
					.put(LogMessage.ACTION, READROLEID)
					.put(LogMessage.MESSAGE, "Access denied: no permission to read roleID of this AppRole")
					.put(LogMessage.APIURL, ThreadLocalContext.getCurrentMap().get(LogMessage.APIURL))
					.build()));
			return roleId;
		}
		log.debug(JSONUtil.getJSON(ImmutableMap.<String, String>builder().
			      put(LogMessage.USER, ThreadLocalContext.getCurrentMap().get(LogMessage.USER)).
				  put(LogMessage.ACTION, READROLEID).
			      put(LogMessage.MESSAGE, String.format("Trying to read role_id for [%s]", rolename)).
			      put(LogMessage.APIURL, ThreadLocalContext.getCurrentMap().get(LogMessage.APIURL)).
			      build()));
		Response readResponse = reqProcessor.process(READPOLEIDPATH,ROLENAMESTR+rolename+"\"}",token);
		Map<String, Object> responseMap = null;
		if(HttpStatus.OK.equals(readResponse.getHttpstatus())) {
			responseMap = ControllerUtil.parseJson(readResponse.getResponse());
			if(responseMap.isEmpty()) {
				log.error(JSONUtil.getJSON(ImmutableMap.<String, String>builder().
					      put(LogMessage.USER, ThreadLocalContext.getCurrentMap().get(LogMessage.USER)).
						  put(LogMessage.ACTION, READROLEID).
					      put(LogMessage.MESSAGE, READROLEFAILMSG).
					      put(LogMessage.APIURL, ThreadLocalContext.getCurrentMap().get(LogMessage.APIURL)).
					      build()));
				return roleId;
			}
			Map<String,Object> roleIdDataMap = (Map<String,Object>) responseMap.get("data");
			if (roleIdDataMap != null) {
				roleId=(String)roleIdDataMap.get("role_id");
			}
			return roleId;
		}
		log.debug(JSONUtil.getJSON(ImmutableMap.<String, String>builder().
			      put(LogMessage.USER, ThreadLocalContext.getCurrentMap().get(LogMessage.USER)).
				  put(LogMessage.ACTION, READROLEID).
			      put(LogMessage.MESSAGE, READROLEFAILMSG).
			      put(LogMessage.APIURL, ThreadLocalContext.getCurrentMap().get(LogMessage.APIURL)).
			      build()));
		return roleId;
	}
	/**
	 * Read accessors of all the SecretIDs issued against the AppRole.
	 * @param token
	 * @param rolename
	 * @return List<String>
	 */
	public List<String> readAccessorIds(String token, String rolename) {
		ArrayList<String> accessorIds = null;
		if (Arrays.asList(TVaultConstants.SELF_SUPPORT_ADMIN_APPROLES).contains(rolename)) {
			log.error(JSONUtil.getJSON(ImmutableMap.<String, String> builder()
					.put(LogMessage.USER, ThreadLocalContext.getCurrentMap().get(LogMessage.USER))
					.put(LogMessage.ACTION, "readAccessorsId")
					.put(LogMessage.MESSAGE, "Access denied: no permission to read roleID of this AppRole")
					.put(LogMessage.APIURL, ThreadLocalContext.getCurrentMap().get(LogMessage.APIURL))
					.build()));
			return accessorIds;
		}
		log.debug(JSONUtil.getJSON(ImmutableMap.<String, String>builder().
			      put(LogMessage.USER, ThreadLocalContext.getCurrentMap().get(LogMessage.USER)).
				  put(LogMessage.ACTION, "readAccessorsIds").
			      put(LogMessage.MESSAGE, String.format("Trying to read accessor_id for [%s]", rolename)).
			      put(LogMessage.APIURL, ThreadLocalContext.getCurrentMap().get(LogMessage.APIURL)).
			      build()));
		Response response = reqProcessor.process("/auth/approle/role/accessors/list",ROLENAMESTR+rolename+"\"}",token);
		Map<String, Object> responseMap = null;
		if(HttpStatus.OK.equals(response.getHttpstatus())) {
			responseMap = ControllerUtil.parseJson(response.getResponse());
			if(responseMap.isEmpty()) {
				log.error(JSONUtil.getJSON(ImmutableMap.<String, String>builder().
					      put(LogMessage.USER, ThreadLocalContext.getCurrentMap().get(LogMessage.USER)).
						  put(LogMessage.ACTION, "readAccessorsIds").
					      put(LogMessage.MESSAGE, "Reading accessor_ids for AppRole failed. No accessor_id information available.").
					      put(LogMessage.APIURL, ThreadLocalContext.getCurrentMap().get(LogMessage.APIURL).toString()).
					      build()));
				return accessorIds;
			}
			accessorIds = (ArrayList<String>) responseMap.get("keys");
			return accessorIds;
		}
		log.debug(JSONUtil.getJSON(ImmutableMap.<String, String>builder().
			      put(LogMessage.USER, ThreadLocalContext.getCurrentMap().get(LogMessage.USER)).
				  put(LogMessage.ACTION, "readAccessorsOfSecretIds").
			      put(LogMessage.MESSAGE, READACCESSCOMPLETEMSG).
			      put(LogMessage.STATUS, response.getHttpstatus().toString()).
			      put(LogMessage.APIURL, ThreadLocalContext.getCurrentMap().get(LogMessage.APIURL)).
			      build()));
		return accessorIds;	
	}

	/**
	 * Reads the metadata associated with an AppRole
	 * @param token
	 * @param rolename
	 * @return AppRoleMetadata
	 */
	public AppRoleMetadata readAppRoleMetadata(String token, String rolename) {
		log.debug(JSONUtil.getJSON(ImmutableMap.<String, String>builder().
			      put(LogMessage.USER, ThreadLocalContext.getCurrentMap().get(LogMessage.USER)).
				  put(LogMessage.ACTION, "readAppRoleMetadata").
			      put(LogMessage.MESSAGE,"Reads the metadata associated with an AppRole.").
			      put(LogMessage.APIURL, ThreadLocalContext.getCurrentMap().get(LogMessage.APIURL)).
			      build()));
		AppRoleMetadata appRoleMetadata = null;
		String path = TVaultConstants.APPROLE_METADATA_MOUNT_PATH + "/" + rolename;
		Response readResponse = reqProcessor.process("/read",PATHSTR+ path +"\"}",token);
		Map<String, Object> responseMap = null;
		if(HttpStatus.OK.equals(readResponse.getHttpstatus())) {
			responseMap = ControllerUtil.parseJson(readResponse.getResponse());
			if(responseMap.isEmpty()) {
				log.error(JSONUtil.getJSON(ImmutableMap.<String, String>builder().
					      put(LogMessage.USER, ThreadLocalContext.getCurrentMap().get(LogMessage.USER)).
						  put(LogMessage.ACTION, "readAppRoleMetadata").
					      put(LogMessage.MESSAGE, "Reading Metadata for AppRole failed").
					      put(LogMessage.APIURL, ThreadLocalContext.getCurrentMap().get(LogMessage.APIURL)).
					      build()));
				return appRoleMetadata;
			}

			Map<String,Object> appRoleMetadataMap = (Map<String,Object>) responseMap.get("data");
			if (appRoleMetadataMap != null) {
				appRoleMetadata = new AppRoleMetadata();
				AppRoleMetadataDetails appRoleMetadataDetails = new AppRoleMetadataDetails();
				appRoleMetadataDetails.setCreatedBy((String)appRoleMetadataMap.get("createdBy"));
				appRoleMetadataDetails.setName(rolename);
				appRoleMetadataDetails.setSharedTo((List<String>) appRoleMetadataMap.get("sharedTo"));
				appRoleMetadata.setAppRoleMetadataDetails(appRoleMetadataDetails);
				appRoleMetadata.setPath(path);
			}
			log.debug(JSONUtil.getJSON(ImmutableMap.<String, String>builder().
				      put(LogMessage.USER, ThreadLocalContext.getCurrentMap().get(LogMessage.USER)).
					  put(LogMessage.ACTION, "readAppRoleMetadata").
				      put(LogMessage.MESSAGE,"Read the metadata associated with an AppRole.").
				      put(LogMessage.APIURL, ThreadLocalContext.getCurrentMap().get(LogMessage.APIURL)).
				      build()));
			return appRoleMetadata;
		}
		else if (HttpStatus.NOT_FOUND.equals(readResponse.getHttpstatus())) {
			log.error(JSONUtil.getJSON(ImmutableMap.<String, String>builder().
				      put(LogMessage.USER, ThreadLocalContext.getCurrentMap().get(LogMessage.USER)).
					  put(LogMessage.ACTION, "getMetaDataForAppRole").
				      put(LogMessage.MESSAGE, "Reading Metadata for AppRole failed. AppRole Not found.").
				      put(LogMessage.APIURL, ThreadLocalContext.getCurrentMap().get(LogMessage.APIURL)).
				      build()));
			return appRoleMetadata;
		}
		log.error(JSONUtil.getJSON(ImmutableMap.<String, String>builder().
			      put(LogMessage.USER, ThreadLocalContext.getCurrentMap().get(LogMessage.USER)).
				  put(LogMessage.ACTION, "getMetaDataForAppRole").
			      put(LogMessage.MESSAGE, "Reading Metadata for AppRole failed").
			      put(LogMessage.APIURL, ThreadLocalContext.getCurrentMap().get(LogMessage.APIURL)).
			      build()));
		return appRoleMetadata;
	}
	
	/**
	 * Reads the AppRole
	 * @param token
	 * @param rolename
	 * @return AppRole
	 */
	public AppRole readAppRoleBasicDetails(String token, String rolename) {
		log.debug(JSONUtil.getJSON(ImmutableMap.<String, String>builder().
			      put(LogMessage.USER, ThreadLocalContext.getCurrentMap().get(LogMessage.USER)).
				  put(LogMessage.ACTION, "readAppRoleBasicDetails").
			      put(LogMessage.MESSAGE,"Start trying  to read AppRole information.").
			      put(LogMessage.APIURL, ThreadLocalContext.getCurrentMap().get(LogMessage.APIURL)).
			      build()));
		AppRole appRole = null;
		if (TVaultConstants.HIDESELFSUPPORTADMINAPPROLE && Arrays.asList(TVaultConstants.SELF_SUPPORT_ADMIN_APPROLES).contains(rolename)) {
			log.error(JSONUtil.getJSON(ImmutableMap.<String, String> builder()
					.put(LogMessage.USER, ThreadLocalContext.getCurrentMap().get(LogMessage.USER))
					.put(LogMessage.ACTION, "readAppRoleBasicDetails")
					.put(LogMessage.MESSAGE, "Access denied: Not enough permission to read the AppRole information")
					.put(LogMessage.APIURL, ThreadLocalContext.getCurrentMap().get(LogMessage.APIURL))
					.build()));
			return appRole;
		}
		Response readResponse = reqProcessor.process(READPATH,ROLENAMESTR+rolename+"\"}",token);
		Map<String, Object> responseMap = null;
		if(HttpStatus.OK.equals(readResponse.getHttpstatus())) {
			responseMap = ControllerUtil.parseJson(readResponse.getResponse());
			if(responseMap.isEmpty()) {
				log.error(JSONUtil.getJSON(ImmutableMap.<String, String>builder().
					      put(LogMessage.USER, ThreadLocalContext.getCurrentMap().get(LogMessage.USER)).
						  put(LogMessage.ACTION, "getAppRole").
					      put(LogMessage.MESSAGE, "Reading AppRole failed").
					      put(LogMessage.APIURL, ThreadLocalContext.getCurrentMap().get(LogMessage.APIURL)).
					      build()));
				return appRole;
			}

			Map<String,Object> appRoleMap = (Map<String,Object>) responseMap.get("data");
			if (appRoleMap != null) {
				String[] policies = null;
				if (appRoleMap.get(POLICIESSTR) != null && ((ArrayList<String>)appRoleMap.get(POLICIESSTR)) != null) {
					ArrayList<String> policiesList = ((ArrayList<String>)appRoleMap.get(POLICIESSTR));
					policies = policiesList.toArray(new String[policiesList.size()]);
				}
				appRole = new AppRole(rolename, 
						policies, 
						((Boolean)appRoleMap.get("bind_secret_id")).booleanValue(),
						((Integer) appRoleMap.get("secret_id_num_uses")),
						((Integer) appRoleMap.get("secret_id_ttl")),
						(Integer)appRoleMap.get("token_num_uses"),
						(Integer)appRoleMap.get("token_ttl"),
						(Integer)appRoleMap.get("token_max_ttl")
						);
			}
			return appRole;
		}
		log.error(JSONUtil.getJSON(ImmutableMap.<String, String>builder().
			      put(LogMessage.USER, ThreadLocalContext.getCurrentMap().get(LogMessage.USER)).
				  put(LogMessage.ACTION, "getAppRole").
			      put(LogMessage.MESSAGE, "Reading AppRole failed").
			      put(LogMessage.APIURL, ThreadLocalContext.getCurrentMap().get(LogMessage.APIURL)).
			      build()));
		return appRole;
	}
	/**
	 * Checks whether given AppRole operation is allowed for a given used based on the ownership of the AppRole
	 * @param userDetails
	 * @param rolename
	 * @return
	 */
	private boolean isAllowed(String rolename, UserDetails userDetails, String operation) {
		boolean isAllowed = false;
		if (userDetails.isAdmin()) {
			// As an admin, I can read, delete, update anybody's AppRole
			isAllowed = true;
		}
		else {
			AppRoleMetadata appRoleMetadata = readAppRoleMetadata(userDetails.getSelfSupportToken(), rolename);
			String appRoleOwner = null;
			if (appRoleMetadata != null && appRoleMetadata.getAppRoleMetadataDetails() != null) {
				appRoleOwner = appRoleMetadata.getAppRoleMetadataDetails().getCreatedBy();
			}
			
			if ((Objects.equals(userDetails.getUsername(), appRoleOwner)) && (TVaultConstants.APPROLE_READ_OPERATION.equals(operation) ||
					TVaultConstants.APPROLE_DELETE_OPERATION.equals(operation) || TVaultConstants.APPROLE_UPDATE_OPERATION.equals(operation))) {
				// As a owner of the AppRole, I can read, delete, update my AppRole
				isAllowed = true;
			} else {
				List<String> sharedTo;
				if (appRoleMetadata != null && appRoleMetadata.getAppRoleMetadataDetails() != null) {
					sharedTo = appRoleMetadata.getAppRoleMetadataDetails().getSharedTo();
					if (sharedTo != null) {
						for (String sharedUser : sharedTo) {
							if (sharedUser.equals(userDetails.getUsername())) {
								isAllowed = true;
								break;
							}
						}
					}
				}
			}
		}

		return isAllowed;
	}
	/**
	 * Checks whether an AppRole exists or not
	 * @param rolename
	 * @param userDetails
	 * @param operation
	 * @return
	 */
	private boolean doesAppRoleExist(String rolename, UserDetails userDetails) {
		boolean exists = false;
		String roleId = null;
		if (userDetails.isAdmin()) {
			roleId = readRoleId(userDetails.getClientToken(), rolename); 
		}
		else {
			roleId = readRoleId(userDetails.getSelfSupportToken(), rolename);
		}
		if (roleId != null) {
			exists = true;
		}
		return exists;
	}
	
	/**
	 * Reads/Gets role_id for AppRole
	 * @param token
	 * @param rolename
	 * @return
	 */
	public ResponseEntity<String> readAppRoleRoleId(String token, String rolename, UserDetails userDetails){

		if ((Arrays.asList(TVaultConstants.SELF_SUPPORT_ADMIN_APPROLES).contains(rolename))) {
			return ResponseEntity.status(HttpStatus.BAD_REQUEST).body("{\"errors\":[\"Access denied: You don't have enough permission to read the role_id associated with the AppRole\"]}");
		}
		log.debug(JSONUtil.getJSON(ImmutableMap.<String, String>builder().
			      put(LogMessage.USER, ThreadLocalContext.getCurrentMap().get(LogMessage.USER)).
				  put(LogMessage.ACTION, READAPPROLEROLEID).
			      put(LogMessage.MESSAGE, String.format("Trying to read role_id for [%s]", rolename)).
			      put(LogMessage.APIURL, ThreadLocalContext.getCurrentMap().get(LogMessage.APIURL)).
			      build()));
		if (!userDetails.isAdmin()) {
			// Non admin owners, who created AppRoles using SelfService feature, need to use SelfSupportToken in order to read role_id
			token = userDetails.getSelfSupportToken();
		}
		AppRole appRole = readAppRoleBasicDetails(token, rolename);
		if (appRole ==null) {
			log.debug(JSONUtil.getJSON(ImmutableMap.<String, String>builder().
				      put(LogMessage.USER, ThreadLocalContext.getCurrentMap().get(LogMessage.USER)).
					  put(LogMessage.ACTION, READAPPROLEROLEID).
				      put(LogMessage.MESSAGE, String.format("Unable to read AppRole information. AppRole [%s] doesn't exist", rolename)).
				      put(LogMessage.APIURL, ThreadLocalContext.getCurrentMap().get(LogMessage.APIURL)).
				      build()));
			return ResponseEntity.status(HttpStatus.OK).body(APPROLENONEXISTSTR);

		}
		boolean isAllowed = isAllowed(rolename, userDetails, TVaultConstants.APPROLE_READ_OPERATION);
		if (isAllowed) {
			Response response = reqProcessor.process(READPOLEIDPATH,ROLENAMESTR+rolename+"\"}",token);
			log.debug(JSONUtil.getJSON(ImmutableMap.<String, String>builder().
				      put(LogMessage.USER, ThreadLocalContext.getCurrentMap().get(LogMessage.USER)).
					  put(LogMessage.ACTION, READAPPROLEROLEID).
				      put(LogMessage.MESSAGE, "Reading AppRoleId completed").
				      put(LogMessage.STATUS, response.getHttpstatus().toString()).
				      put(LogMessage.APIURL, ThreadLocalContext.getCurrentMap().get(LogMessage.APIURL)).
				      build()));
			return ResponseEntity.status(response.getHttpstatus()).body(response.getResponse());	
		}
		log.error(JSONUtil.getJSON(ImmutableMap.<String, String>builder().
			      put(LogMessage.USER, ThreadLocalContext.getCurrentMap().get(LogMessage.USER)).
				  put(LogMessage.ACTION, READAPPROLEROLEID).
			      put(LogMessage.MESSAGE, READROLEFAILMSG).
			      put(LogMessage.APIURL, ThreadLocalContext.getCurrentMap().get(LogMessage.APIURL)).
			      build()));
		return ResponseEntity.status(HttpStatus.BAD_REQUEST).body("{\"errors\":[\"Access denied: You don't have enough permission to read the role_id associated with the AppRole\"]}");
	}
	/**
	 * Reads/Gets secret_id for AppRole
	 * @param token
	 * @param rolename
	 * @return
	 */
	public ResponseEntity<String> readAppRoleSecretId(String token, String rolename, UserDetails userDetails){

		if (Arrays.asList(TVaultConstants.SELF_SUPPORT_ADMIN_APPROLES).contains(rolename)){
			return ResponseEntity.status(HttpStatus.BAD_REQUEST).body("{\"errors\":[\"Access denied: You don't have enough permission to read the secret_id associated with the AppRole\"]}");
		}
		log.debug(JSONUtil.getJSON(ImmutableMap.<String, String>builder().
			      put(LogMessage.USER, ThreadLocalContext.getCurrentMap().get(LogMessage.USER)).
				  put(LogMessage.ACTION, READAPPROLESECRETID).
			      put(LogMessage.MESSAGE, String.format("Trying to read secret_id for the Role[%s]", rolename)).
			      put(LogMessage.APIURL, ThreadLocalContext.getCurrentMap().get(LogMessage.APIURL)).
			      build()));
		if (!userDetails.isAdmin()) {
			// Non owners, who created AppRoles using SelfService feature, need to use SelfSupportToken in order to read secret_id
			token = userDetails.getSelfSupportToken();
		}
		AppRole appRole = readAppRoleBasicDetails(token, rolename);
		if (appRole ==null) {
			log.debug(JSONUtil.getJSON(ImmutableMap.<String, String>builder().
				      put(LogMessage.USER, ThreadLocalContext.getCurrentMap().get(LogMessage.USER)).
					  put(LogMessage.ACTION, READAPPROLESECRETID).
				      put(LogMessage.MESSAGE, "Unable to read AppRole. AppRole does not exist.").
				      put(LogMessage.APIURL, ThreadLocalContext.getCurrentMap().get(LogMessage.APIURL)).
				      build()));
			return ResponseEntity.status(HttpStatus.OK).body(APPROLENONEXISTSTR);

		}
		boolean isAllowed = isAllowed(rolename, userDetails, TVaultConstants.APPROLE_READ_OPERATION);
		if (isAllowed) {
			Response response = reqProcessor.process("/auth/approle/secretid/lookup",ROLENAMESTR+rolename+"\"}",token);
			log.debug(JSONUtil.getJSON(ImmutableMap.<String, String>builder().
				      put(LogMessage.USER, ThreadLocalContext.getCurrentMap().get(LogMessage.USER)).
					  put(LogMessage.ACTION, READAPPROLESECRETID).
				      put(LogMessage.MESSAGE, "Reading AppRoleId completed").
				      put(LogMessage.STATUS, response.getHttpstatus().toString()).
				      put(LogMessage.APIURL, ThreadLocalContext.getCurrentMap().get(LogMessage.APIURL)).
				      build()));
			return ResponseEntity.status(response.getHttpstatus()).body(response.getResponse());	
		}
		log.error(JSONUtil.getJSON(ImmutableMap.<String, String>builder().
			      put(LogMessage.USER, ThreadLocalContext.getCurrentMap().get(LogMessage.USER)).
				  put(LogMessage.ACTION, READAPPROLESECRETID).
			      put(LogMessage.MESSAGE, "Reading secret_id for AppRole failed").
			      put(LogMessage.APIURL, ThreadLocalContext.getCurrentMap().get(LogMessage.APIURL)).
			      build()));
		return ResponseEntity.status(HttpStatus.BAD_REQUEST).body("{\"errors\":[\"Access denied: You don't have enough permission to read the secret_id associated with the AppRole\"]}");
	}
	/**
	 * Read accessors of all the SecretIDs issued against the AppRole.
	 * @param token
	 * @param rolename
	 * @param userDetails
	 * @return
	 */
	public ResponseEntity<String> readSecretIdAccessors(String token, String rolename, UserDetails userDetails){

		if (Arrays.asList(TVaultConstants.SELF_SUPPORT_ADMIN_APPROLES).contains(rolename)) {
			return ResponseEntity.status(HttpStatus.BAD_REQUEST).body(
					"{\"errors\":[\"Access denied: You don't have enough permission to read the accessors of SecretIds associated with the AppRole\"]}");
		}
		log.debug(JSONUtil.getJSON(ImmutableMap.<String, String>builder().
			      put(LogMessage.USER, ThreadLocalContext.getCurrentMap().get(LogMessage.USER)).
				  put(LogMessage.ACTION, SECRETIDACCESSORS).
			      put(LogMessage.MESSAGE, String.format("Trying to read accessors of all the SecretIDs [%s]", rolename)).
			      put(LogMessage.APIURL, ThreadLocalContext.getCurrentMap().get(LogMessage.APIURL)).
			      build()));
		if (!userDetails.isAdmin()) {
			// Non owners, who created AppRoles using SelfService feature, need to use SelfSupportToken in order to read secret_id
			token = userDetails.getSelfSupportToken();
		}
		if (!doesAppRoleExist(rolename, userDetails)) {
			log.debug(JSONUtil.getJSON(ImmutableMap.<String, String>builder().
				      put(LogMessage.USER, ThreadLocalContext.getCurrentMap().get(LogMessage.USER)).
					  put(LogMessage.ACTION, SECRETIDACCESSORS).
				      put(LogMessage.MESSAGE, "Unable to read accessors of all the SecretIDs. AppRole may not exist").
				      put(LogMessage.APIURL, ThreadLocalContext.getCurrentMap().get(LogMessage.APIURL)).
				      build()));
			return ResponseEntity.status(HttpStatus.OK).body("{\"errors\":[\"Unable to read AppRole. AppRole does not exist.\"]}");
		}
		boolean isAllowed = isAllowed(rolename, userDetails, TVaultConstants.APPROLE_READ_OPERATION);
		if (isAllowed) {
			Response response = reqProcessor.process("/auth/approle/role/accessors/list",ROLENAMESTR+rolename+"\"}",token);
			if(HttpStatus.OK.equals(response.getHttpstatus())) {
				log.debug(JSONUtil.getJSON(ImmutableMap.<String, String>builder().
					      put(LogMessage.USER, ThreadLocalContext.getCurrentMap().get(LogMessage.USER)).
						  put(LogMessage.ACTION, SECRETIDACCESSORS).
					      put(LogMessage.MESSAGE, READACCESSCOMPLETEMSG).
					      put(LogMessage.STATUS, response.getHttpstatus().toString()).
					      put(LogMessage.APIURL, ThreadLocalContext.getCurrentMap().get(LogMessage.APIURL)).
					      build()));
				return ResponseEntity.status(response.getHttpstatus()).body(response.getResponse());
			}
			else if (HttpStatus.NOT_FOUND.equals(response.getHttpstatus())) {
				log.debug(JSONUtil.getJSON(ImmutableMap.<String, String>builder().
					      put(LogMessage.USER, ThreadLocalContext.getCurrentMap().get(LogMessage.USER)).
						  put(LogMessage.ACTION, SECRETIDACCESSORS).
					      put(LogMessage.MESSAGE, "Reading accessors of all the SecretIDs for AppRole completed. There are no accessor_ids.").
					      put(LogMessage.STATUS, response.getHttpstatus().toString()).
					      put(LogMessage.APIURL, ThreadLocalContext.getCurrentMap().get(LogMessage.APIURL)).
					      build()));
				return ResponseEntity.status(HttpStatus.OK).body("{\"keys\":[]}");
			}
			else {
				log.debug(JSONUtil.getJSON(ImmutableMap.<String, String>builder().
					      put(LogMessage.USER, ThreadLocalContext.getCurrentMap().get(LogMessage.USER)).
						  put(LogMessage.ACTION, SECRETIDACCESSORS).
					      put(LogMessage.MESSAGE, READACCESSCOMPLETEMSG).
					      put(LogMessage.STATUS, response.getHttpstatus().toString()).
					      put(LogMessage.APIURL, ThreadLocalContext.getCurrentMap().get(LogMessage.APIURL)).
					      build()));
				return ResponseEntity.status(HttpStatus.BAD_REQUEST).body("{\"errors\":[\"Not able to read accessor_ids.\"]}");
			}

		}
		log.error(JSONUtil.getJSON(ImmutableMap.<String, String>builder().
			      put(LogMessage.USER, ThreadLocalContext.getCurrentMap().get(LogMessage.USER)).
				  put(LogMessage.ACTION, SECRETIDACCESSORS).
			      put(LogMessage.MESSAGE, "Reading accessors of all the SecretIDs for AppRole failed").
			      put(LogMessage.APIURL, ThreadLocalContext.getCurrentMap().get(LogMessage.APIURL)).
			      build()));
		return ResponseEntity.status(HttpStatus.BAD_REQUEST).body("{\"errors\":[\"Access denied: You don't have enough permission to read the accessors of SecretIds associated with the AppRole\"]}");
	}
	
	/**
	 * Reads/Gets AppRole details
	 * @param token
	 * @param rolename
	 * @return
	 */
	public ResponseEntity<String> readAppRoleDetails(String token, String rolename, UserDetails userDetails){

		if (Arrays.asList(TVaultConstants.SELF_SUPPORT_ADMIN_APPROLES).contains(rolename)) {
			return ResponseEntity.status(HttpStatus.BAD_REQUEST).body(
					"{\"errors\":[\"Access denied: You don't have enough permission to read the information of the AppRole\"]}");
		}
		log.debug(JSONUtil.getJSON(ImmutableMap.<String, String>builder().
			      put(LogMessage.USER, ThreadLocalContext.getCurrentMap().get(LogMessage.USER)).
				  put(LogMessage.ACTION, "readAppRoleDetails").
			      put(LogMessage.MESSAGE, String.format("Trying to read AppRole information for [%s]", rolename)).
			      put(LogMessage.APIURL, ThreadLocalContext.getCurrentMap().get(LogMessage.APIURL)).
			      build()));
		if (!userDetails.isAdmin()) {
			// Non owners, who created AppRoles using SelfService feature, need to use SelfSupportToken in order to read secret_id
			token = userDetails.getSelfSupportToken();
		}
		AppRole appRole = readAppRoleBasicDetails(token, rolename);
		if (appRole ==null) {
			log.debug(JSONUtil.getJSON(ImmutableMap.<String, String>builder().
				      put(LogMessage.USER, ThreadLocalContext.getCurrentMap().get(LogMessage.USER)).
					  put(LogMessage.ACTION, READAPPROLESECRETID).
				      put(LogMessage.MESSAGE, String.format("Unable to read AppRole information. AppRole [%s] doesn't exist", rolename)).
				      put(LogMessage.APIURL, ThreadLocalContext.getCurrentMap().get(LogMessage.APIURL)).
				      build()));
			return ResponseEntity.status(HttpStatus.BAD_REQUEST).body(APPROLENONEXISTSTR);

		}
		boolean isAllowed = isAllowed(rolename, userDetails, TVaultConstants.APPROLE_READ_OPERATION);
		if (isAllowed) {
			AppRoleMetadata appRoleMetadata = readAppRoleMetadata(token, rolename);
			String roleId = readRoleId(token, rolename);
			List<String> accessorIds = readAccessorIds(token, rolename);
			
			AppRoleDetails appRoleDetails = new AppRoleDetails();
			appRoleDetails.setRole_name(appRole.getRole_name());
			appRoleDetails.setPolicies(appRole.getPolicies());
			appRoleDetails.setBind_secret_id(appRole.isBind_secret_id());
			appRoleDetails.setSecret_id_num_uses(appRole.getSecret_id_num_uses());
			appRoleDetails.setSecret_id_ttl(appRole.getSecret_id_ttl());
			appRoleDetails.setToken_num_uses(appRole.getToken_num_uses());
			appRoleDetails.setToken_ttl(appRole.getToken_ttl());
			appRoleDetails.setToken_max_ttl(appRole.getToken_max_ttl());
			appRoleDetails.setRole_id(roleId);
			appRoleDetails.setAppRoleMetadata(appRoleMetadata);
			if (!CollectionUtils.isEmpty(accessorIds)) {
				appRoleDetails.setAccessorIds(accessorIds.toArray(new String[accessorIds.size()]));
			}
			// Create Response object
			Response response = new Response();
			response.setHttpstatus(HttpStatus.OK);
			response.setSuccess(true);
			response.setResponse(JSONUtil.getJSON(appRoleDetails));
			return ResponseEntity.status(response.getHttpstatus()).body(response.getResponse());	
		}
		log.error(JSONUtil.getJSON(ImmutableMap.<String, String>builder().
			      put(LogMessage.USER, ThreadLocalContext.getCurrentMap().get(LogMessage.USER)).
				  put(LogMessage.ACTION, READAPPROLESECRETID).
			      put(LogMessage.MESSAGE, "Reading secret_id for AppRole failed").
			      put(LogMessage.APIURL, ThreadLocalContext.getCurrentMap().get(LogMessage.APIURL)).
			      build()));
		return ResponseEntity.status(HttpStatus.BAD_REQUEST).body("{\"errors\":[\"Access denied: You don't have enough permission to read the secret_id associated with the AppRole\"]}");
	}
	/**
	 * Creates secret id for approle auth
	 * @param token
	 * @param jsonStr
	 * @return
	 */
	public ResponseEntity<String> createsecretId(String token, AppRoleSecretData appRoleSecretData){
		log.debug(JSONUtil.getJSON(ImmutableMap.<String, String>builder().
			      put(LogMessage.USER, ThreadLocalContext.getCurrentMap().get(LogMessage.USER)).
				  put(LogMessage.ACTION, "CreateSecretId").
			      put(LogMessage.MESSAGE, String.format("Trying to create SecretId for  [%s]",appRoleSecretData.getRole_name() )).
			      put(LogMessage.APIURL, ThreadLocalContext.getCurrentMap().get(LogMessage.APIURL)).
			      build()));
		if (Arrays.asList(TVaultConstants.SELF_SUPPORT_ADMIN_APPROLES).contains(appRoleSecretData.getRole_name())){
			return ResponseEntity.status(HttpStatus.BAD_REQUEST).body("{\"errors\":[\"Access denied: no permission to create secretID for this AppRole\"]}");
		}
		String jsonStr = JSONUtil.getJSON(appRoleSecretData);
		log.debug(JSONUtil.getJSON(ImmutableMap.<String, String>builder().
			      put(LogMessage.USER, ThreadLocalContext.getCurrentMap().get(LogMessage.USER)).
				  put(LogMessage.ACTION, "CreateSecretId").
			      put(LogMessage.MESSAGE, String.format("Trying to create SecretId for the role [%s]", appRoleSecretData.getRole_name())).
			      put(LogMessage.APIURL, ThreadLocalContext.getCurrentMap().get(LogMessage.APIURL)).
			      build()));
		jsonStr = ControllerUtil.convertAppRoleSecretIdToLowerCase(jsonStr);
		Response response = reqProcessor.process("/auth/approle/secretid/create", jsonStr,token);
		if(response.getHttpstatus().equals(HttpStatus.NO_CONTENT)) {
			log.debug(JSONUtil.getJSON(ImmutableMap.<String, String>builder().
				      put(LogMessage.USER, ThreadLocalContext.getCurrentMap().get(LogMessage.USER)).
					  put(LogMessage.ACTION, "Create SecretId").
				      put(LogMessage.MESSAGE, "Create SecretId completed successfully").
				      put(LogMessage.STATUS, response.getHttpstatus().toString()).
				      put(LogMessage.APIURL, ThreadLocalContext.getCurrentMap().get(LogMessage.APIURL)).
				      build()));
			return ResponseEntity.status(HttpStatus.OK).body("{\"messages\":[\"Secret ID created for AppRole\"]}");
		}
		log.error(JSONUtil.getJSON(ImmutableMap.<String, String>builder().
			      put(LogMessage.USER, ThreadLocalContext.getCurrentMap().get(LogMessage.USER)).
				  put(LogMessage.ACTION, "Create SecretId").
			      put(LogMessage.MESSAGE, "Create SecretId failed").
			      put(LogMessage.RESPONSE, response.getResponse()).
			      put(LogMessage.STATUS, response.getHttpstatus().toString()).
			      put(LogMessage.APIURL, ThreadLocalContext.getCurrentMap().get(LogMessage.APIURL)).
			      build()));
		return ResponseEntity.status(response.getHttpstatus()).body(response.getResponse());	
	}
	/**
	 * Reads secret id for a given rolename
	 * @param token
	 * @param rolename
	 * @return
	 */
	public ResponseEntity<String> readAppRoleSecretId(String token, String rolename){
		log.debug(JSONUtil.getJSON(ImmutableMap.<String, String>builder().
			      put(LogMessage.USER, ThreadLocalContext.getCurrentMap().get(LogMessage.USER)).
				  put(LogMessage.ACTION, "Read SecretId").
			      put(LogMessage.MESSAGE, String.format("Trying to read SecretId for the role [%s]", rolename)).
			      put(LogMessage.APIURL, ThreadLocalContext.getCurrentMap().get(LogMessage.APIURL)).
			      build()));
		if (Arrays.asList(TVaultConstants.SELF_SUPPORT_ADMIN_APPROLES).contains(rolename)) {
			return ResponseEntity.status(HttpStatus.BAD_REQUEST)
					.body("{\"errors\":[\"Access denied: no permission to read secretID for this AppRole\"]}");
		}
		Response response = reqProcessor.process("/auth/approle/secretid/lookup",ROLENAMESTR+rolename+"\"}",token);
		log.debug(JSONUtil.getJSON(ImmutableMap.<String, String>builder().
			      put(LogMessage.USER, ThreadLocalContext.getCurrentMap().get(LogMessage.USER)).
				  put(LogMessage.ACTION, "Read SecretId").
			      put(LogMessage.MESSAGE, "Read SecretId completed").
			      put(LogMessage.STATUS, response.getHttpstatus().toString()).
			      put(LogMessage.APIURL, ThreadLocalContext.getCurrentMap().get(LogMessage.APIURL)).
			      build()));
		return ResponseEntity.status(response.getHttpstatus()).body(response.getResponse());	
	}
	/**
	 * Deletes Secret id
	 * @param token
	 * @param jsonStr
	 * @return
	 */
	public ResponseEntity<String> deleteSecretId(String token, AppRoleNameSecretId appRoleNameSecretId){
		log.debug(JSONUtil.getJSON(ImmutableMap.<String, String>builder().
			      put(LogMessage.USER, ThreadLocalContext.getCurrentMap().get(LogMessage.USER)).
				  put(LogMessage.ACTION, "DeleteSecretId").
			      put(LogMessage.MESSAGE, String.format("Trying to delete SecretId for the role [%s].",appRoleNameSecretId.getRole_name())).
			      put(LogMessage.APIURL, ThreadLocalContext.getCurrentMap().get(LogMessage.APIURL)).
			      build()));
		if (Arrays.asList(TVaultConstants.SELF_SUPPORT_ADMIN_APPROLES).contains(appRoleNameSecretId.getRole_name())){
			return ResponseEntity.status(HttpStatus.BAD_REQUEST).body("{\"errors\":[\"Access denied: no permission to delete secretId for this approle\"]}");
		}
		String jsonStr = JSONUtil.getJSON(appRoleNameSecretId);
		Response response = reqProcessor.process("/auth/approle/secret/delete",jsonStr,token);
		if(response.getHttpstatus().equals(HttpStatus.NO_CONTENT)) {
			log.debug(JSONUtil.getJSON(ImmutableMap.<String, String>builder().
				      put(LogMessage.USER, ThreadLocalContext.getCurrentMap().get(LogMessage.USER)).
					  put(LogMessage.ACTION, "Delete SecretId").
				      put(LogMessage.MESSAGE, "Deletion of SecretId completed successfully").
				      put(LogMessage.STATUS, response.getHttpstatus().toString()).
				      put(LogMessage.APIURL, ThreadLocalContext.getCurrentMap().get(LogMessage.APIURL)).
				      build()));
			return ResponseEntity.status(HttpStatus.OK).body("{\"messages\":[\"SecretId for AppRole deleted\"]}");
		}
		log.error(JSONUtil.getJSON(ImmutableMap.<String, String>builder().
			      put(LogMessage.USER, ThreadLocalContext.getCurrentMap().get(LogMessage.USER)).
				  put(LogMessage.ACTION, "Delete SecretId").
			      put(LogMessage.MESSAGE, "Deletion of SecretId failed").
			      put(LogMessage.RESPONSE, response.getResponse()).
			      put(LogMessage.STATUS, response.getHttpstatus().toString()).
			      put(LogMessage.APIURL, ThreadLocalContext.getCurrentMap().get(LogMessage.APIURL)).
			      build()));
		return ResponseEntity.status(response.getHttpstatus()).body(response.getResponse());	
	}
	/**
	 * Deletes an approle
	 * @param token
	 * @param rolename
	 * @return
	 */
	public ResponseEntity<String> deleteAppRole(String token, AppRole appRole, UserDetails userDetails){
		log.debug(JSONUtil.getJSON(ImmutableMap.<String, String>builder().
				put(LogMessage.USER, ThreadLocalContext.getCurrentMap().get(LogMessage.USER)).
				put(LogMessage.ACTION, DELETE_APPROLE).
				put(LogMessage.MESSAGE, String.format("Start trying to delete approle [%s].", appRole.getRole_name())).
				put(LogMessage.APIURL, ThreadLocalContext.getCurrentMap().get(LogMessage.APIURL)).
				build()));
		if (Arrays.asList(TVaultConstants.SELF_SUPPORT_ADMIN_APPROLES).contains(appRole.getRole_name())){
			log.error(JSONUtil.getJSON(ImmutableMap.<String, String>builder().
				      put(LogMessage.USER, ThreadLocalContext.getCurrentMap().get(LogMessage.USER)).
					  put(LogMessage.ACTION, DELETE_APPROLE).
				      put(LogMessage.MESSAGE, "Access denied: no permission to remove this AppRole").
				      put(LogMessage.APIURL, ThreadLocalContext.getCurrentMap().get(LogMessage.APIURL)).
				      build()));
			return ResponseEntity.status(HttpStatus.BAD_REQUEST).body("{\"errors\":[\"Access denied: no permission to remove this AppRole\"]}");
		}
		Response permissionResponse =  ControllerUtil.canDeleteRole(appRole.getRole_name(), token, userDetails, TVaultConstants.APPROLE_METADATA_MOUNT_PATH);
		if (HttpStatus.INTERNAL_SERVER_ERROR.equals(permissionResponse.getHttpstatus()) || HttpStatus.UNAUTHORIZED.equals(permissionResponse.getHttpstatus())) {
			return ResponseEntity.status(HttpStatus.BAD_REQUEST).body("{\"errors\":[\""+permissionResponse.getResponse()+"\"]}");
		}

		token = userDetails.getSelfSupportToken();
		
		Response roleResponse = reqProcessor.process(READPATH,ROLENAMESTR+appRole.getRole_name()+"\"}",token);
		String responseJson="";
		List<String> policies = new ArrayList<>();
		List<String> currentpolicies = new ArrayList<>();
		if(HttpStatus.OK.equals(roleResponse.getHttpstatus())){
			responseJson = roleResponse.getResponse();
			ObjectMapper objMapper = new ObjectMapper();
			try {
				JsonNode policiesArry = objMapper.readTree(responseJson).get("data").get(POLICIESSTR);
				if (null != policiesArry) {
					for(JsonNode policyNode : policiesArry){
						currentpolicies.add(policyNode.asText());
					}
				}
			} catch (IOException e) {
				log.error(e);
			}
			policies.addAll(currentpolicies);
		}
		for(String policy :policies) {
			String name = null;
			String[] parts = policy.split("_");
			String type = "";
			if (parts.length > 1) {
				type = parts[1];
			} else {
				continue;
			}

			if(policy.startsWith("r_cert_") || policy.startsWith("w_cert_") || policy.startsWith("d_cert_") || policy.startsWith("o_cert_")) {
				 name=policy.substring(7);
			}
			if(policy.startsWith("r_externalcerts_") || policy.startsWith("w_externalcerts_") || policy.startsWith("d_externalcerts_") || policy.startsWith("o_externalcerts_")) {
				name=policy.substring(16);
			}
			if(policy.startsWith("r_users_") || policy.startsWith("w_users_") || policy.startsWith("d_users_")) {
				name=policy.substring(8);
			}
			if(policy.startsWith("r_shared_") || policy.startsWith("w_shared_") || policy.startsWith("d_shared_")) {
				name=policy.substring(9);
			}
			if(policy.startsWith("r_apps_") || policy.startsWith("w_apps_") || policy.startsWith("d_apps_")) {
				name=policy.substring(7);
			}
			if(policy.startsWith("r_iamsvcacc_") || policy.startsWith("w_iamsvcacc_") || policy.startsWith("d_iamsvcacc_") || policy.startsWith("o_iamsvcacc_")) {
				name=policy.substring(12);
			}
			if(policy.startsWith("r_svcacct_") || policy.startsWith("w_svcacct_") || policy.startsWith("d_svcacct_") || policy.startsWith("o_svcacct_")) {
				name=policy.substring(10);
			}
			if(policy.startsWith("r_azuresvcacc_") || policy.startsWith("w_azuresvcacc_") || policy.startsWith("d_azuresvcacc_")) {
				name=policy.substring(14);
			}
			//Internal Certificate
			if(policy.startsWith("r_cert_") || policy.startsWith("w_cert_") || policy.startsWith("d_cert_") || policy.startsWith("o_cert_") ) {
				String certificatePath = SSLCertificateConstants.SSL_CERT_PATH_VALUE + name;
				Map<String,String> params = new HashMap<>();
				params.put("type", TVaultConstants.UPDATE_METADATA_PARAM);
				params.put("name",appRole.getRole_name());
				params.put("path",certificatePath);
				params.put(ACCESS,TVaultConstants.DELETE_APPROLE_PERMISSION_PARAM);
				Response metadataResponse = ControllerUtil.updateMetadata(params, token);
				if(metadataResponse !=null && (HttpStatus.NO_CONTENT.equals(metadataResponse.getHttpstatus()) || HttpStatus.OK.equals(metadataResponse.getHttpstatus()))){
					log.debug(JSONUtil.getJSON(ImmutableMap.<String, String>builder().
							put(LogMessage.USER, ThreadLocalContext.getCurrentMap().get(LogMessage.USER)).
							put(LogMessage.ACTION, SSLCertificateConstants.ADD_APPROLE_TO_CERT_MSG).
							put(LogMessage.MESSAGE, String.format("Approle [%s] successfully deleted from Internal Certificate [%s]", appRole.getRole_name(), certificatePath)).
							put(LogMessage.STATUS, metadataResponse.getHttpstatus().toString()).
							put(LogMessage.APIURL, ThreadLocalContext.getCurrentMap().get(LogMessage.APIURL)).
							build()));
				}
			}
			//External Certificate
			if(policy.startsWith("r_externalcerts_") || policy.startsWith("w_externalcerts_") || policy.startsWith("d_externalcerts_") || policy.startsWith("o_externalcerts_") ) {
				String certificatePath = SSLCertificateConstants.SSL_CERT_PATH_VALUE_EXT + name;
				Map<String,String> params = new HashMap<>();
				params.put("type", TVaultConstants.UPDATE_METADATA_PARAM);
				params.put("name",appRole.getRole_name());
				params.put("path",certificatePath);
				params.put(ACCESS,TVaultConstants.DELETE_APPROLE_PERMISSION_PARAM);
				Response metadataResponse = ControllerUtil.updateMetadata(params, token);
				if(metadataResponse !=null && (HttpStatus.NO_CONTENT.equals(metadataResponse.getHttpstatus()) || HttpStatus.OK.equals(metadataResponse.getHttpstatus()))){
					log.debug(JSONUtil.getJSON(ImmutableMap.<String, String>builder().
							put(LogMessage.USER, ThreadLocalContext.getCurrentMap().get(LogMessage.USER)).
							put(LogMessage.ACTION, SSLCertificateConstants.ADD_APPROLE_TO_CERT_MSG).
							put(LogMessage.MESSAGE, String.format("Approle [%s] successfully deleted from  External Certificate [%s]", appRole.getRole_name(), certificatePath)).
							put(LogMessage.STATUS, metadataResponse.getHttpstatus().toString()).
							put(LogMessage.APIURL, ThreadLocalContext.getCurrentMap().get(LogMessage.APIURL)).
							build()));
				}
			}
			
		//SAFE
			if(policy.startsWith("r_users_") || policy.startsWith("w_users_") || policy.startsWith("d_users_") ||policy.startsWith("r_shared_") || policy.startsWith("w_shared_") || policy.startsWith("d_shared_") ||policy.startsWith("r_apps_") || policy.startsWith("w_apps_") || policy.startsWith("d_apps_")){
				String safePath = type + '/' + name;
				Map<String,String> params = new HashMap<>();
				params.put("type", TVaultConstants.UPDATE_METADATA_PARAM);
				params.put("name",appRole.getRole_name());
				params.put("path",safePath);
				params.put(ACCESS,TVaultConstants.DELETE_APPROLE_PERMISSION_PARAM);
				Response metadataResponse = ControllerUtil.updateMetadata(params, token);
				if(metadataResponse !=null && (HttpStatus.NO_CONTENT.equals(metadataResponse.getHttpstatus()) || HttpStatus.OK.equals(metadataResponse.getHttpstatus()))){
				log.debug(JSONUtil.getJSON(ImmutableMap.<String, String>builder().
						put(LogMessage.USER, ThreadLocalContext.getCurrentMap().get(LogMessage.USER)).
						put(LogMessage.ACTION, SSLCertificateConstants.ADD_APPROLE_TO_CERT_MSG).
						put(LogMessage.MESSAGE, String.format("Approle [%s] successfully deleted from safe [%s]", appRole.getRole_name(), safePath)).
						put(LogMessage.STATUS, metadataResponse.getHttpstatus().toString()).
						put(LogMessage.APIURL, ThreadLocalContext.getCurrentMap().get(LogMessage.APIURL)).
						build()));
				
			}
		}
			//IAM Service Account
			if(policy.startsWith("r_iamsvcacc_") || policy.startsWith("w_iamsvcacc_") || policy.startsWith("d_iamsvcacc_") || policy.startsWith("o_iamsvcacc_") ) {
				String iamPath = IAMServiceAccountConstants.IAM_SVCC_ACC_PATH +name;
				Map<String,String> params = new HashMap<>();
				params.put("type", TVaultConstants.UPDATE_METADATA_PARAM);
				params.put("name",appRole.getRole_name());
				params.put("path",iamPath);
				params.put(ACCESS,TVaultConstants.DELETE_APPROLE_PERMISSION_PARAM);
				Response metadataResponse = ControllerUtil.updateMetadata(params, token);
				if(metadataResponse !=null && (HttpStatus.NO_CONTENT.equals(metadataResponse.getHttpstatus()) || HttpStatus.OK.equals(metadataResponse.getHttpstatus()))){
					log.debug(JSONUtil.getJSON(ImmutableMap.<String, String>builder().
							put(LogMessage.USER, ThreadLocalContext.getCurrentMap().get(LogMessage.USER)).
							put(LogMessage.ACTION, SSLCertificateConstants.ADD_APPROLE_TO_CERT_MSG).
							put(LogMessage.MESSAGE, String.format("Approle [%s] successfully deleted from IAM Service Account [%s]", appRole.getRole_name(), iamPath)).
							put(LogMessage.STATUS, metadataResponse.getHttpstatus().toString()).
							put(LogMessage.APIURL, ThreadLocalContext.getCurrentMap().get(LogMessage.APIURL)).
							build()));
				}
			}
			//AD Service Account
			if(policy.startsWith("r_svcacct_") || policy.startsWith("w_svcacct_") || policy.startsWith("d_svcacct_") || policy.startsWith("o_svcacct_") ) {
				String serviceAccountPath = TVaultConstants.SVC_ACC_ROLES_PATH + name;
				Map<String,String> params = new HashMap<>();
				params.put("type", TVaultConstants.UPDATE_METADATA_PARAM);
				params.put("name",appRole.getRole_name());
				params.put("path",serviceAccountPath);
				params.put(ACCESS,TVaultConstants.DELETE_APPROLE_PERMISSION_PARAM);
				Response metadataResponse = ControllerUtil.updateMetadata(params, token);
				if(metadataResponse !=null && (HttpStatus.NO_CONTENT.equals(metadataResponse.getHttpstatus()) || HttpStatus.OK.equals(metadataResponse.getHttpstatus()))){
					log.debug(JSONUtil.getJSON(ImmutableMap.<String, String>builder().
							put(LogMessage.USER, ThreadLocalContext.getCurrentMap().get(LogMessage.USER)).
							put(LogMessage.ACTION, SSLCertificateConstants.ADD_APPROLE_TO_CERT_MSG).
							put(LogMessage.MESSAGE, String.format("Approle [%s] successfully deleted from Service Account [%s]", appRole.getRole_name(), serviceAccountPath)).
							put(LogMessage.STATUS, metadataResponse.getHttpstatus().toString()).
							put(LogMessage.APIURL, ThreadLocalContext.getCurrentMap().get(LogMessage.APIURL)).
							build()));
				}
			}
			//Azure Service Account
			if(policy.startsWith("r_azuresvcacc_") || policy.startsWith("w_azuresvcacc_") || policy.startsWith("d_azuresvcacc_") || policy.startsWith("o_azuresvcacc_") ) {
				String azureServiceAccountPath = AzureServiceAccountConstants.AZURE_SVCC_ACC_PATH + name;
				Map<String,String> params = new HashMap<>();
				params.put("type", TVaultConstants.UPDATE_METADATA_PARAM);
				params.put("name",appRole.getRole_name());
				params.put("path",azureServiceAccountPath);
				params.put(ACCESS,TVaultConstants.DELETE_APPROLE_PERMISSION_PARAM);
				Response metadataResponse = ControllerUtil.updateMetadata(params, token);
				if(metadataResponse !=null && (HttpStatus.NO_CONTENT.equals(metadataResponse.getHttpstatus()) || HttpStatus.OK.equals(metadataResponse.getHttpstatus()))){
					log.debug(JSONUtil.getJSON(ImmutableMap.<String, String>builder().
							put(LogMessage.USER, ThreadLocalContext.getCurrentMap().get(LogMessage.USER)).
							put(LogMessage.ACTION, SSLCertificateConstants.ADD_APPROLE_TO_CERT_MSG).
							put(LogMessage.MESSAGE, String.format("Approle [%s] successfully deleted from Azure Service Account [%s]", appRole.getRole_name(), azureServiceAccountPath)).
							put(LogMessage.STATUS, metadataResponse.getHttpstatus().toString()).
							put(LogMessage.APIURL, ThreadLocalContext.getCurrentMap().get(LogMessage.APIURL)).
							build()));
				}
			}
			
		}
		String jsonStr = JSONUtil.getJSON(appRole);
		log.debug(JSONUtil.getJSON(ImmutableMap.<String, String>builder().
			      put(LogMessage.USER, ThreadLocalContext.getCurrentMap().get(LogMessage.USER)).
				  put(LogMessage.ACTION, "Delete AppRoleId").
			      put(LogMessage.MESSAGE, String.format("Trying to delete AppRoleId [%s]", jsonStr)).
			      put(LogMessage.APIURL, ThreadLocalContext.getCurrentMap().get(LogMessage.APIURL)).
			      build()));
		AppRoleMetadata appRoleMetadata = readAppRoleMetadata(token, appRole.getRole_name());
		
		String approleCreatedBy = userDetails.getUsername();
		if ( appRoleMetadata.getAppRoleMetadataDetails() != null) {
			approleCreatedBy = appRoleMetadata.getAppRoleMetadataDetails().getCreatedBy();
		}
		Response response = reqProcessor.process("/auth/approle/role/delete",jsonStr,token);
		if(response.getHttpstatus().equals(HttpStatus.NO_CONTENT)) {
			log.debug(JSONUtil.getJSON(ImmutableMap.<String, String>builder().
				      put(LogMessage.USER, ThreadLocalContext.getCurrentMap().get(LogMessage.USER)).
					  put(LogMessage.ACTION, DELETE_APPROLE).
				      put(LogMessage.MESSAGE, "Delete AppRole completed").
				      put(LogMessage.STATUS, response.getHttpstatus().toString()).
				      put(LogMessage.APIURL, ThreadLocalContext.getCurrentMap().get(LogMessage.APIURL)).
				      build()));
			// delete metadata
			String jsonstr = ControllerUtil.populateAppRoleMetaJson(appRole, userDetails.getUsername());
			Response resp = reqProcessor.process("/delete",jsonstr,token);
			String appRoleUsermetadataJson = ControllerUtil.populateUserMetaJson(appRole, approleCreatedBy);
			Response appRoleUserMetaDataDeletionResponse = reqProcessor.process("/delete",appRoleUsermetadataJson,token);
			boolean appRoleSharedToUserMetaDataCreationStatus = true;
			List<String> sharedToList = appRoleMetadata.getAppRoleMetadataDetails().getSharedTo();
			if (sharedToList != null) {
				String appRoleSharedToMetadataJson;
				Response appRoleSharedToUserMetaDataDeletionResponse;
				for (String sharedToUser : sharedToList) {
					if (StringUtils.isNotEmpty(sharedToUser)) {
						appRoleSharedToMetadataJson = ControllerUtil.populateSharedToUserMetaJson(userDetails.getUsername(), sharedToUser, appRole);
						appRoleSharedToUserMetaDataDeletionResponse = reqProcessor.process("/delete", appRoleSharedToMetadataJson, token);
						appRoleSharedToUserMetaDataCreationStatus = appRoleSharedToUserMetaDataDeletionResponse.getHttpstatus().equals(HttpStatus.NO_CONTENT);
					}
				}
			}
			
			if (HttpStatus.NO_CONTENT.equals(resp.getHttpstatus()) && HttpStatus.NO_CONTENT.equals(appRoleUserMetaDataDeletionResponse.getHttpstatus()) &&
					appRoleSharedToUserMetaDataCreationStatus) {
				log.debug(JSONUtil.getJSON(ImmutableMap.<String, String>builder().
					      put(LogMessage.USER, ThreadLocalContext.getCurrentMap().get(LogMessage.USER)).
						  put(LogMessage.ACTION, DELETE_APPROLE).
					      put(LogMessage.MESSAGE, "AppRole delete completed").
					      put(LogMessage.STATUS, response.getHttpstatus().toString()).
					      put(LogMessage.APIURL, ThreadLocalContext.getCurrentMap().get(LogMessage.APIURL)).
					      build()));
				return ResponseEntity.status(HttpStatus.OK).body("{\"messages\":[\"AppRole deleted\"]}");
			}
			return ResponseEntity.status(HttpStatus.OK).body("{\"messages\":[\"AppRole deleted, metadata delete failed\"]}");
		}
		log.error(JSONUtil.getJSON(ImmutableMap.<String, String>builder().
			      put(LogMessage.USER, ThreadLocalContext.getCurrentMap().get(LogMessage.USER)).
				  put(LogMessage.ACTION, DELETE_APPROLE).
			      put(LogMessage.MESSAGE, "Delete AppRole failed").
			      put(LogMessage.RESPONSE, response.getResponse()).
			      put(LogMessage.STATUS, response.getHttpstatus().toString()).
			      put(LogMessage.APIURL, ThreadLocalContext.getCurrentMap().get(LogMessage.APIURL)).
			      build()));
		return ResponseEntity.status(response.getHttpstatus()).body(response.getResponse());
	}
	/**
	 * Deletes the SecretIds generated for the given AppRole
	 * @param token
	 * @param appRoleAccessorIds
	 * @param userDetails
	 * @return ResponseEntity<String>
	 */
	public ResponseEntity<String> deleteSecretIds(String token, AppRoleAccessorIds appRoleAccessorIds, UserDetails userDetails){
		log.debug(JSONUtil.getJSON(ImmutableMap.<String, String>builder().
			      put(LogMessage.USER, ThreadLocalContext.getCurrentMap().get(LogMessage.USER)).
				  put(LogMessage.ACTION, "DeleteSecretId").
			      put(LogMessage.MESSAGE, String.format("Trying to delete SecretId for the role [%s].",appRoleAccessorIds.getRole_name())).
			      put(LogMessage.APIURL, ThreadLocalContext.getCurrentMap().get(LogMessage.APIURL)).
			      build()));
		if (Arrays.asList(TVaultConstants.SELF_SUPPORT_ADMIN_APPROLES).contains(appRoleAccessorIds.getRole_name())) {
			return ResponseEntity.status(HttpStatus.BAD_REQUEST)
					.body(String.format(
							"{\"errors\":[\"Access denied: You don't have enough permission to delete the secret_ids associated with the AppRole (%s) \"]}",
							appRoleAccessorIds.getRole_name()));
		}
		boolean isAllowed = isAllowed(appRoleAccessorIds.getRole_name(), userDetails, TVaultConstants.APPROLE_DELETE_OPERATION);
		if (!userDetails.isAdmin()) {
			// Non admin owners, who created AppRoles using SelfService feature, need to use SelfSupportToken in order to read role_id
			token = userDetails.getSelfSupportToken();
		}
		if (isAllowed) {
			String[] accessorIds = appRoleAccessorIds.getAccessorIds();
			ArrayList<String> failedAccessorIds = new ArrayList<>();
			ArrayList<String> deletedAccessorIds = new ArrayList<>();
			for (String accessorId: accessorIds) {
				log.debug(JSONUtil.getJSON(ImmutableMap.<String, String>builder().
					      put(LogMessage.USER, ThreadLocalContext.getCurrentMap().get(LogMessage.USER)).
						  put(LogMessage.ACTION, DELETESECRET).
					      put(LogMessage.MESSAGE, String.format("Trying to read SecretId for accessorId [%s]", accessorId)).
					      put(LogMessage.APIURL, ThreadLocalContext.getCurrentMap().get(LogMessage.APIURL)).
					      build()));
				String jsonStr = JSONUtil.getJSON(new AppRoleAccessorId(appRoleAccessorIds.getRole_name(), accessorId));
				Response deleteSecretIdResponse = reqProcessor.process("/auth/approle/role/delete/secretids",jsonStr,token);
				if(HttpStatus.NO_CONTENT.equals(deleteSecretIdResponse.getHttpstatus())) {
					deletedAccessorIds.add(accessorId);
					log.error(JSONUtil.getJSON(ImmutableMap.<String, String>builder().
						      put(LogMessage.USER, ThreadLocalContext.getCurrentMap().get(LogMessage.USER)).
							  put(LogMessage.ACTION, DELETESECRET).
						      put(LogMessage.MESSAGE, String.format("Successfully deleted SecretId for the accessor_id [%s]",accessorId)).
						      put(LogMessage.APIURL, ThreadLocalContext.getCurrentMap().get(LogMessage.APIURL)).
						      build())); 
				}
				else if (HttpStatus.INTERNAL_SERVER_ERROR.equals(deleteSecretIdResponse.getHttpstatus()) && 
					deleteSecretIdResponse.getResponse().contains("failed to find accessor entry for secret_id_accessor")) {
					failedAccessorIds.add(accessorId);
					log.debug(JSONUtil.getJSON(ImmutableMap.<String, String>builder().
						      put(LogMessage.USER, ThreadLocalContext.getCurrentMap().get(LogMessage.USER)).
							  put(LogMessage.ACTION, DELETESECRET).
						      put(LogMessage.MESSAGE, String.format("Unable to delete SecretId for the accessor_id [%s] since accessor_id does not exist",accessorId)).
						      put(LogMessage.APIURL, ThreadLocalContext.getCurrentMap().get(LogMessage.APIURL)).
						      build()));
				}
				else {
					failedAccessorIds.add(accessorId);
					log.error(JSONUtil.getJSON(ImmutableMap.<String, String>builder().
						      put(LogMessage.USER, ThreadLocalContext.getCurrentMap().get(LogMessage.USER)).
							  put(LogMessage.ACTION, DELETESECRET).
						      put(LogMessage.MESSAGE, String.format("Unable to delete SecretId for the accessor_id [%s]",accessorId)).
						      put(LogMessage.APIURL, ThreadLocalContext.getCurrentMap().get(LogMessage.APIURL)).
						      build()));
				}
			}
			StringBuilder message = new StringBuilder("Deletion of secret_ids completed as: ");
			if (!CollectionUtils.isEmpty(deletedAccessorIds)) {
				message.append(String.format("Succssfully deleted the secret_ids for the following accessor_ids: [%s]. ",StringUtils.join(deletedAccessorIds.toArray(), ",")));
			}
			if (!CollectionUtils.isEmpty(failedAccessorIds)) {
				message.append(String.format("Failed to delete the secret_ids for the following accessor_ids: [%s]",StringUtils.join(failedAccessorIds.toArray(), ",")));
			}
			log.debug(JSONUtil.getJSON(ImmutableMap.<String, String>builder().
				      put(LogMessage.USER, ThreadLocalContext.getCurrentMap().get(LogMessage.USER)).
					  put(LogMessage.ACTION, DELETESECRET).
				      put(LogMessage.MESSAGE,"Deletion of SecretId completed successfully").
				      put(LogMessage.APIURL, ThreadLocalContext.getCurrentMap().get(LogMessage.APIURL)).
				      build()));
			return ResponseEntity.status(HttpStatus.OK).body("{\"messages\":[\""+message+"\"]}");
		}
		log.error(JSONUtil.getJSON(ImmutableMap.<String, String>builder().
			      put(LogMessage.USER, ThreadLocalContext.getCurrentMap().get(LogMessage.USER)).
				  put(LogMessage.ACTION, DELETESECRET).
			      put(LogMessage.MESSAGE, "Deleting deleteSecretIds for AppRole failed").
			      put(LogMessage.APIURL, ThreadLocalContext.getCurrentMap().get(LogMessage.APIURL)).
			      build()));
		return ResponseEntity.status(HttpStatus.BAD_REQUEST).body("{\"errors\":[\"Access denied: You don't have enough permission to delete the secret_ids associated with the AppRole\"]}");

	}
	/**
	 * Login using appRole
	 * @param appRoleIdSecretId
	 * @return
	 */
	public ResponseEntity<String> login(AppRoleIdSecretId appRoleIdSecretId){
		String jsonStr = JSONUtil.getJSON(appRoleIdSecretId);
		log.debug(JSONUtil.getJSON(ImmutableMap.<String, String>builder().
			      put(LogMessage.USER, ThreadLocalContext.getCurrentMap().get(LogMessage.USER)).
				  put(LogMessage.ACTION, "AppRoleLogin").
			      put(LogMessage.MESSAGE, "Start trying to authenticate with AppRole.").
			      put(LogMessage.APIURL, ThreadLocalContext.getCurrentMap().get(LogMessage.APIURL)).
			      build()));
		Response response = reqProcessor.process("/auth/approle/login",jsonStr,"");
		if(HttpStatus.OK.equals(response.getHttpstatus())) {
			log.debug(JSONUtil.getJSON(ImmutableMap.<String, String>builder().
				      put(LogMessage.USER, ThreadLocalContext.getCurrentMap().get(LogMessage.USER)).
					  put(LogMessage.ACTION, "AppRole Login").
				      put(LogMessage.MESSAGE, "AppRole Authentication Successful.").
				      put(LogMessage.STATUS, response.getHttpstatus().toString()).
				      put(LogMessage.APIURL, ThreadLocalContext.getCurrentMap().get(LogMessage.APIURL)).
				      build()));
			return ResponseEntity.status(response.getHttpstatus()).body(response.getResponse());
		}
		else {
			log.error(JSONUtil.getJSON(ImmutableMap.<String, String>builder().
				      put(LogMessage.USER, ThreadLocalContext.getCurrentMap().get(LogMessage.USER)).
					  put(LogMessage.ACTION, "AppRole Login").
				      put(LogMessage.MESSAGE, "AppRole Authentication failed.").
				      put(LogMessage.RESPONSE, response.getResponse()).
				      put(LogMessage.STATUS, response.getHttpstatus().toString()).
				      put(LogMessage.APIURL, ThreadLocalContext.getCurrentMap().get(LogMessage.APIURL)).
				      build()));
			return ResponseEntity.status(response.getHttpstatus()).body("{\"errors\":[\"Approle Login Failed.\"]}" + "HTTP STATUSCODE  :" + response.getHttpstatus());
		}
	}
	/**
	 * Associates an AppRole to a Safe
	 * @param token
	 * @param safeAppRoleAccess
	 * @return
	 */
	public ResponseEntity<String> associateApprole(String token, SafeAppRoleAccess safeAppRoleAccess){

		if (Arrays.asList(TVaultConstants.SELF_SUPPORT_ADMIN_APPROLES).contains(safeAppRoleAccess.getRole_name())) {
			return ResponseEntity.status(HttpStatus.BAD_REQUEST).body("{\"errors\":[\"Access denied: no permission to associate this AppRole to any safe\"]}");
		}
		ResponseEntity<String> response = associateApproletoSafe(token,safeAppRoleAccess);
		if(response.getStatusCode().equals(HttpStatus.NO_CONTENT)) {
			return ResponseEntity.status(HttpStatus.OK).body("{\"messages\":[\"Approle associated to SDB\"]}");
		}
		else if(response.getStatusCode().equals(HttpStatus.OK)) {
			return ResponseEntity.status(HttpStatus.OK).body("{\"messages\":[\"Approle associated to SDB\"]}");
		}
		else {
			return ResponseEntity.status(response.getStatusCode()).body(response.getBody());
		}
	}
	
	/**
	 * Associates an AppRole to a Safe
	 * @param token
	 * @param safeAppRoleAccess
	 * @return
	 */
	private ResponseEntity<String>associateApproletoSafe(String token,  SafeAppRoleAccess safeAppRoleAccess){
		String jsonstr = JSONUtil.getJSON(safeAppRoleAccess);
		log.debug(JSONUtil.getJSON(ImmutableMap.<String, String>builder().
			      put(LogMessage.USER, ThreadLocalContext.getCurrentMap().get(LogMessage.USER)).
				  put(LogMessage.ACTION, ASSOCIATEAPPROLE).
			      put(LogMessage.MESSAGE, String.format ("Trying to associate AppRole to SDB [%s]", jsonstr)).
			      put(LogMessage.APIURL, ThreadLocalContext.getCurrentMap().get(LogMessage.APIURL)).
			      build()));		
		
		Map<String,Object> requestMap = ControllerUtil.parseJson(jsonstr);
		if(!ControllerUtil.areSafeAppRoleInputsValid(requestMap)) {
			return ResponseEntity.status(HttpStatus.BAD_REQUEST).body("{\"errors\":[\"Invalid input values\"]}");
		}
		String approle = requestMap.get("role_name").toString();
		String path = requestMap.get("path").toString();
		String access = requestMap.get(ACCESS).toString();
		
		boolean canAddAppRole = ControllerUtil.canAddPermission(path, token);
		if(canAddAppRole){

			log.info(JSONUtil.getJSON(ImmutableMap.<String, String>builder().
				      put(LogMessage.USER, ThreadLocalContext.getCurrentMap().get(LogMessage.USER)).
					  put(LogMessage.ACTION, ASSOCIATEAPPROLE).
				      put(LogMessage.MESSAGE, String.format ("Associate approle to SDB -  path :  [%s] valid", path)).
				      put(LogMessage.APIURL, ThreadLocalContext.getCurrentMap().get(LogMessage.APIURL)).
				      build()));	

			String[] folders = path.split("[/]+");
			
			String policy ="";
			
			switch (access){
				case TVaultConstants.READ_POLICY: policy = "r_" + folders[0].toLowerCase() + "_" + folders[1] ; break ;
				case TVaultConstants.WRITE_POLICY: policy = "w_"  + folders[0].toLowerCase() + "_" + folders[1] ;break;
				case TVaultConstants.DENY_POLICY: policy = "d_"  + folders[0].toLowerCase() + "_" + folders[1] ;break;
			}
			String policyPostfix = folders[0].toLowerCase() + "_" + folders[1];
			Response roleResponse = reqProcessor.process(READPATH,ROLENAMESTR+approle+"\"}",token);
			String responseJson="";
			List<String> policies = new ArrayList<>();
			List<String> currentpolicies = new ArrayList<>();
			if(HttpStatus.OK.equals(roleResponse.getHttpstatus())){
				responseJson = roleResponse.getResponse();
				ObjectMapper objMapper = new ObjectMapper();
				try {
					JsonNode policiesArry = objMapper.readTree(responseJson).get("data").get(POLICIESSTR);
					if (null != policiesArry) {
						for (JsonNode policyNode : policiesArry) {
							currentpolicies.add(policyNode.asText());
						}
					}
				} catch (IOException e) {
					log.error(e);
				}
				policies.addAll(currentpolicies);

				policies.remove("r_"+policyPostfix);
				policies.remove("w_"+policyPostfix);
				policies.remove("d_"+policyPostfix);

			} else {
				return ResponseEntity.status(HttpStatus.UNPROCESSABLE_ENTITY).body("{\"errors\":[\"Non existing role name. Please configure approle as first step\"]}");
			}

			if(TVaultConstants.EMPTY.equals(policy)){
				return ResponseEntity.status(HttpStatus.UNPROCESSABLE_ENTITY).body("{\"errors\":[\"Incorrect access requested. Valid values are read,write,deny \"]}");
			}
			policies.add(policy);
			String policiesString = StringUtils.join(policies, ",");
			String currentpoliciesString = StringUtils.join(currentpolicies, ",");

			log.info(JSONUtil.getJSON(ImmutableMap.<String, String>builder().
					put(LogMessage.USER, ThreadLocalContext.getCurrentMap().get(LogMessage.USER)).
					put(LogMessage.ACTION, ASSOCIATEAPPROLE).
					put(LogMessage.MESSAGE, "Associate approle to SDB -  policy :" + policiesString + " is being configured" ).
		  			put(LogMessage.APIURL, ThreadLocalContext.getCurrentMap().get(LogMessage.APIURL)).
					build()));
			//Call controller to update the policy for approle
			Response approleControllerResp = configureApprole(approle,policiesString,token);
			if(HttpStatus.OK.equals(approleControllerResp.getHttpstatus()) || (HttpStatus.NO_CONTENT.equals(approleControllerResp.getHttpstatus()))) {

				log.debug(JSONUtil.getJSON(ImmutableMap.<String, String>builder().
					      put(LogMessage.USER, ThreadLocalContext.getCurrentMap().get(LogMessage.USER)).
						  put(LogMessage.ACTION, ASSOCIATEAPPROLE).
					      put(LogMessage.MESSAGE, "Associate approle to SDB -  policy :" + policiesString + " is associated").
					      put(LogMessage.STATUS, approleControllerResp.getHttpstatus().toString()).
					      put(LogMessage.APIURL, ThreadLocalContext.getCurrentMap().get(LogMessage.APIURL)).
					      build()));
				Map<String,String> params = new HashMap<>();
				params.put("type", "app-roles");
				params.put("name",approle);
				params.put("path",path);
				params.put(ACCESS,access);
				Response metadataResponse = ControllerUtil.updateMetadata(params,token);
				if(metadataResponse != null && HttpStatus.NO_CONTENT.equals(metadataResponse.getHttpstatus())){
					log.debug(JSONUtil.getJSON(ImmutableMap.<String, String>builder().
						      put(LogMessage.USER, ThreadLocalContext.getCurrentMap().get(LogMessage.USER)).
							  put(LogMessage.ACTION, "Add AppRole To SDB").
						      put(LogMessage.MESSAGE, "AppRole is successfully associated").
						      put(LogMessage.STATUS, metadataResponse.getHttpstatus().toString()).
						      put(LogMessage.APIURL, ThreadLocalContext.getCurrentMap().get(LogMessage.APIURL)).
						      build()));
					return ResponseEntity.status(HttpStatus.OK).body("{\"messages\":[\"Approle :" + approle + " is successfully associated with SDB\"]}");		
				}else{
					String safeType = ControllerUtil.getSafeType(path);
					String safeName = ControllerUtil.getSafeName(path);
					List<String> safeNames = ControllerUtil.getAllExistingSafeNames(safeType, token);
					String newPath = path;
					if (safeNames != null ) {
						
						for (String existingSafeName: safeNames) {
							if (existingSafeName.equalsIgnoreCase(safeName)) {
								// It will come here when there is only one valid safe
								newPath = safeType + "/" + existingSafeName;
								break;
							}
						} 
						
					}
					params.put("path",newPath);
					metadataResponse = ControllerUtil.updateMetadata(params,token);
					if(metadataResponse !=null && HttpStatus.NO_CONTENT.equals(metadataResponse.getHttpstatus())){
						log.debug(JSONUtil.getJSON(ImmutableMap.<String, String>builder().
							      put(LogMessage.USER, ThreadLocalContext.getCurrentMap().get(LogMessage.USER)).
								  put(LogMessage.ACTION, "Add AppRole To SDB").
							      put(LogMessage.MESSAGE, "AppRole is successfully associated").
							      put(LogMessage.STATUS, metadataResponse.getHttpstatus().toString()).
							      put(LogMessage.APIURL, ThreadLocalContext.getCurrentMap().get(LogMessage.APIURL)).
							      build()));
						return ResponseEntity.status(HttpStatus.OK).body("{\"messages\":[\"Approle :" + approle + " is successfully associated with SDB\"]}");		
					}
					else {
						log.debug(JSONUtil.getJSON(ImmutableMap.<String, String>builder().
							      put(LogMessage.USER, ThreadLocalContext.getCurrentMap().get(LogMessage.USER)).
								  put(LogMessage.ACTION, "Add AppRole To SDB").
							      put(LogMessage.MESSAGE, "AppRole configuration failed.").
							      put(LogMessage.RESPONSE, (null!=metadataResponse)?metadataResponse.getResponse():TVaultConstants.EMPTY).
							      put(LogMessage.STATUS, (null!=metadataResponse)?metadataResponse.getHttpstatus().toString():TVaultConstants.EMPTY).
							      put(LogMessage.APIURL, ThreadLocalContext.getCurrentMap().get(LogMessage.APIURL).toString()).
							      build()));
						//Trying to revert the metadata update in case of failure
						approleControllerResp = configureApprole(approle,currentpoliciesString,token);
						if(approleControllerResp.getHttpstatus().equals(HttpStatus.NO_CONTENT)){
							log.error(JSONUtil.getJSON(ImmutableMap.<String, String>builder().
								      put(LogMessage.USER, ThreadLocalContext.getCurrentMap().get(LogMessage.USER)).
									  put(LogMessage.ACTION, "Add AppRole To SDB").
								      put(LogMessage.MESSAGE, "Reverting user policy update failed").
								      put(LogMessage.RESPONSE, (null!=metadataResponse)?metadataResponse.getResponse():TVaultConstants.EMPTY).
								      put(LogMessage.STATUS, (null!=metadataResponse)?metadataResponse.getHttpstatus().toString():TVaultConstants.EMPTY).
								      put(LogMessage.APIURL, ThreadLocalContext.getCurrentMap().get(LogMessage.APIURL)).
								      build()));
							return ResponseEntity.status(HttpStatus.INTERNAL_SERVER_ERROR).body("{\"errors\":[\"Role configuration failed.Please try again\"]}");
						}else{
							log.error(JSONUtil.getJSON(ImmutableMap.<String, String>builder().
								      put(LogMessage.USER, ThreadLocalContext.getCurrentMap().get(LogMessage.USER)).
									  put(LogMessage.ACTION, "Add AppRole To SDB").
								      put(LogMessage.MESSAGE, "Reverting user policy update failed").
								      put(LogMessage.RESPONSE, (null!=metadataResponse)?metadataResponse.getResponse():TVaultConstants.EMPTY).
								      put(LogMessage.STATUS, (null!=metadataResponse)?metadataResponse.getHttpstatus().toString():TVaultConstants.EMPTY).
								      put(LogMessage.APIURL, ThreadLocalContext.getCurrentMap().get(LogMessage.APIURL)).
								      build()));
							return ResponseEntity.status(HttpStatus.INTERNAL_SERVER_ERROR).body("{\"errors\":[\"Role configuration failed.Contact Admin \"]}");
						}
					}
				}
			
		}else {
			log.error(JSONUtil.getJSON(ImmutableMap.<String, String>builder().
				      put(LogMessage.USER, ThreadLocalContext.getCurrentMap().get(LogMessage.USER)).
					  put(LogMessage.ACTION, ASSOCIATEAPPROLE).
				      put(LogMessage.MESSAGE, "Association of AppRole to SDB failed").
				      put(LogMessage.RESPONSE, approleControllerResp.getResponse()).
				      put(LogMessage.STATUS, approleControllerResp.getHttpstatus().toString()).
				      put(LogMessage.APIURL, ThreadLocalContext.getCurrentMap().get(LogMessage.APIURL)).
				      build()));
				log.error( "Associate Approle {} to sdb FAILED", approle);
				return ResponseEntity.status(HttpStatus.BAD_REQUEST).body("{\"messages\":[\"Approle :" + approle + " failed to be associated with SDB\"]}");		
			}
		} else {
			log.error(JSONUtil.getJSON(ImmutableMap.<String, String>builder().
				      put(LogMessage.USER, ThreadLocalContext.getCurrentMap().get(LogMessage.USER)).
					  put(LogMessage.ACTION, ASSOCIATEAPPROLE).
				      put(LogMessage.MESSAGE, "Association of AppRole to SDB failed").
				      put(LogMessage.RESPONSE, "Invalid Path").
				      put(LogMessage.APIURL, ThreadLocalContext.getCurrentMap().get(LogMessage.APIURL)).
				      build()));
			return ResponseEntity.status(HttpStatus.BAD_REQUEST).body("{\"messages\":[\"Approle :" + approle + " failed to be associated with SDB.. Invalid Path specified\"]}");		
		
		}
	}

	/**
	 * Updates an AppRole, including ability to transfer ownership.
	 * @param token
	 * @param appRoleUpdate
	 * @param userDetails
	 * @return ResponseEntity
	 */
	public ResponseEntity<String> updateAppRole(String token, AppRoleUpdate appRoleUpdate, UserDetails userDetails) {
		log.debug(JSONUtil.getJSON(ImmutableMap.<String, String>builder().
			      put(LogMessage.USER, ThreadLocalContext.getCurrentMap().get(LogMessage.USER)).
				  put(LogMessage.ACTION,UPDATE_APPROLE).
			      put(LogMessage.MESSAGE, String.format("Start trying to update AppRole [%s]", appRoleUpdate.getRole_name())).
			      put(LogMessage.APIURL, ThreadLocalContext.getCurrentMap().get(LogMessage.APIURL)).
			      build()));
		if (StringUtils.isEmpty(appRoleUpdate.getRole_name())) {
			log.error(JSONUtil.getJSON(ImmutableMap.<String, String>builder().
				      put(LogMessage.USER, ThreadLocalContext.getCurrentMap().get(LogMessage.USER)).
					  put(LogMessage.ACTION, UPDATE_APPROLE).
				      put(LogMessage.MESSAGE, "Not enough information to update AppRole").
				      put(LogMessage.APIURL, ThreadLocalContext.getCurrentMap().get(LogMessage.APIURL)).
				      build()));
			return ResponseEntity.status(HttpStatus.BAD_REQUEST).body(
					"{\"errors\":[\"AppRole can't be updated since insufficient information has been provided.\"]}");
		}
		if ((appRoleUpdate.getOwner() != null && appRoleUpdate.getNew_owner_email() == null) ||
				(appRoleUpdate.getOwner() == null && appRoleUpdate.getNew_owner_email() != null)) {
			log.error(JSONUtil.getJSON(ImmutableMap.<String, String>builder().
					put(LogMessage.USER, ThreadLocalContext.getCurrentMap().get(LogMessage.USER)).
					put(LogMessage.ACTION, UPDATE_APPROLE).
					put(LogMessage.MESSAGE, "Could not update AppRole because user either didn't provide a new owner, or a new_owner_email.").
					put(LogMessage.APIURL, ThreadLocalContext.getCurrentMap().get(LogMessage.APIURL)).
					build()));
			return ResponseEntity.status(HttpStatus.BAD_REQUEST).body(
					"{\"errors\":[\"If you provide an owner you must also provide a new_owner_email, and vice versa.\"]}");
		}

		AppRole appRole = constructAppRoleFromUpdateObject(appRoleUpdate);
		String rolename = appRole.getRole_name();

		if (Arrays.asList(TVaultConstants.SELF_SUPPORT_ADMIN_APPROLES).contains(rolename)) {
			return ResponseEntity.status(HttpStatus.BAD_REQUEST).body("{\"errors\":[\"Access denied: You don't have enough permission to modify the AppRole information\"]}");
		}
		log.debug(JSONUtil.getJSON(ImmutableMap.<String, String>builder().
			      put(LogMessage.USER, ThreadLocalContext.getCurrentMap().get(LogMessage.USER)).
				  put(LogMessage.ACTION, UPDATE_APPROLE).
			      put(LogMessage.MESSAGE, String.format("Trying to update AppRole [%s]", rolename)).
			      put(LogMessage.APIURL, ThreadLocalContext.getCurrentMap().get(LogMessage.APIURL)).
			      build()));
		if (!userDetails.isAdmin()) {
			// Non owners, who created AppRoles using SelfService feature, need to use SelfSupportToken in order to read secret_id
			token = userDetails.getSelfSupportToken();
		}

		AppRoleMetadata appRoleMetadata = readAppRoleMetadata(token, rolename);
		AppRoleMetadataDetails appRoleMetadataDetails;
		if (appRoleMetadata != null) {
			appRoleMetadataDetails = appRoleMetadata.getAppRoleMetadataDetails();
		} else {
			log.error(JSONUtil.getJSON(ImmutableMap.<String, String>builder().
					put(LogMessage.USER, ThreadLocalContext.getCurrentMap().get(LogMessage.USER)).
					put(LogMessage.ACTION, UPDATE_APPROLE).
					put(LogMessage.MESSAGE, "Could not update AppRole because metadata for it could not be found.").
					put(LogMessage.APIURL, ThreadLocalContext.getCurrentMap().get(LogMessage.APIURL)).
					build()));
			return ResponseEntity.status(HttpStatus.BAD_REQUEST).body(
					"{\"errors\":[\"AppRole doesn't exist.\"]}");
		}

		boolean isSharedToChanged = isSharedToChanged(appRoleMetadataDetails, appRole.getShared_to());
		boolean isOwnershipChanged = false;
		if (appRoleUpdate.getOwner() != null) {
			if (!userDetails.getUsername().equals(appRoleMetadataDetails.getCreatedBy()) && !userDetails.isAdmin()) {
				log.error(JSONUtil.getJSON(ImmutableMap.<String, String>builder().
						put(LogMessage.USER, ThreadLocalContext.getCurrentMap().get(LogMessage.USER)).
						put(LogMessage.ACTION, UPDATE_APPROLE).
						put(LogMessage.MESSAGE, String.format("Unable to transfer owner on AppRole [%s] because user %s is not the owner or admin.",
								rolename, appRoleUpdate.getOwner())).
						put(LogMessage.APIURL, ThreadLocalContext.getCurrentMap().get(LogMessage.APIURL)).
						build()));
				return ResponseEntity.status(HttpStatus.BAD_REQUEST).body(String.format(
						"{\"errors\":[\"Unable to transfer ownership of AppRole %s because you are not the owner of the AppRole or an admin user.\"]}",
						rolename, appRoleUpdate.getOwner()));
			}
			if (appRoleMetadataDetails.getCreatedBy().equals(appRoleUpdate.getOwner())) {
				log.error(JSONUtil.getJSON(ImmutableMap.<String, String>builder().
						put(LogMessage.USER, ThreadLocalContext.getCurrentMap().get(LogMessage.USER)).
						put(LogMessage.ACTION, UPDATE_APPROLE).
						put(LogMessage.MESSAGE, String.format("Unable to transfer owner on AppRole [%s] because [%s] is already the owner",
								rolename, appRoleUpdate.getOwner())).
						put(LogMessage.APIURL, ThreadLocalContext.getCurrentMap().get(LogMessage.APIURL)).
						build()));
				return ResponseEntity.status(HttpStatus.BAD_REQUEST).body(String.format(
						"{\"errors\":[\"Unable to transfer ownership of AppRole %s because %s is already the owner\"]}",
						rolename, appRoleUpdate.getOwner()));
			}

			boolean newOwnerIsSharedUser = false;
			if (appRoleUpdate.getShared_to() == null &&
					(appRoleMetadataDetails.getSharedTo() != null && appRoleMetadataDetails.getSharedTo().contains(appRoleUpdate.getOwner()))) {
				newOwnerIsSharedUser = true;
			}
			if (appRoleUpdate.getShared_to() != null && appRoleUpdate.getShared_to().contains(appRoleUpdate.getOwner())) {
				newOwnerIsSharedUser = true;
			}
			if (newOwnerIsSharedUser) {
				log.error(JSONUtil.getJSON(ImmutableMap.<String, String>builder().
						put(LogMessage.USER, ThreadLocalContext.getCurrentMap().get(LogMessage.USER)).
						put(LogMessage.ACTION, UPDATE_APPROLE).
						put(LogMessage.MESSAGE, String.format("Unable to share AppRole [%s] with [%s] because they are the existing owner.",
								rolename, appRoleUpdate.getOwner())).
						put(LogMessage.APIURL, ThreadLocalContext.getCurrentMap().get(LogMessage.APIURL)).
						build()));
				return ResponseEntity.status(HttpStatus.BAD_REQUEST).body(String.format(
						"{\"errors\":[\"An AppRole cannot be shared with its owner. Please remove owner %s as a shared user, " +
								"or change the owner.\"]}", appRoleUpdate.getOwner()));
			}
			isOwnershipChanged = !appRoleUpdate.getOwner().isEmpty();
		}

		if (!isOwnershipChanged && !validateNoSharedUserIsOwner(appRoleMetadataDetails, appRole.getShared_to())) {
			return ResponseEntity.status(HttpStatus.INTERNAL_SERVER_ERROR)
					.body("{\"errors\":[\"An AppRole cannot be shared with the current owner\"]}");
		}

		boolean isAppRoleOwner = isAppRoleOwner(userDetails.getUsername(), appRoleMetadataDetails);
		if (!userDetails.isAdmin() && (isSharedToChanged && !isAppRoleOwner)) {
			log.error(JSONUtil.getJSON(ImmutableMap.<String, String>builder().
					put(LogMessage.USER, ThreadLocalContext.getCurrentMap().get(LogMessage.USER)).
					put(LogMessage.ACTION, UPDATE_APPROLE).
					put(LogMessage.MESSAGE, String.format("Unable to update shared_to on AppRole [%s] because [%s] is not the owner",
							rolename, userDetails.getUsername())).
					put(LogMessage.APIURL, ThreadLocalContext.getCurrentMap().get(LogMessage.APIURL)).
					build()));
			return ResponseEntity.status(HttpStatus.UNAUTHORIZED).body(
					String.format("{\"errors\":[\"Unable to update shared_to on AppRole %s because you are not the owner\"]}", rolename));
		}

		AppRole existingAppRole = readAppRoleBasicDetails(token, rolename);
		if (existingAppRole == null) {
			log.debug(JSONUtil.getJSON(ImmutableMap.<String, String>builder().
				      put(LogMessage.USER, ThreadLocalContext.getCurrentMap().get(LogMessage.USER)).
					  put(LogMessage.ACTION, UPDATE_APPROLE).
				      put(LogMessage.MESSAGE, String.format("Unable to read AppRole information. AppRole [%s] doesn't exist", rolename)).
				      put(LogMessage.APIURL, ThreadLocalContext.getCurrentMap().get(LogMessage.APIURL)).
				      build()));
			return ResponseEntity.status(HttpStatus.OK).body(APPROLENONEXISTSTR);
		}

		appRole.setPolicies(existingAppRole.getPolicies());
		appRole.setBind_secret_id(existingAppRole.isBind_secret_id());
		String jsonStr = JSONUtil.getJSON(appRole);

		Response response = reqProcessor.process(CREATEPATH, jsonStr,token);
		if(response.getHttpstatus().equals(HttpStatus.NO_CONTENT) || response.getHttpstatus().equals(HttpStatus.OK)) {
			log.debug(JSONUtil.getJSON(ImmutableMap.<String, String>builder().
				      put(LogMessage.USER, ThreadLocalContext.getCurrentMap().get(LogMessage.USER)).
					  put(LogMessage.ACTION, UPDATE_APPROLE).
				      put(LogMessage.MESSAGE, "AppRole updated successfully").
				      put(LogMessage.APIURL, ThreadLocalContext.getCurrentMap().get(LogMessage.APIURL)).
				      build()));

			if (null == appRole.getShared_to()) {
				appRole.setShared_to(appRoleMetadataDetails.getSharedTo());
			}

			if (isSharedToChanged || isOwnershipChanged) {
				String username = userDetails.getUsername();
				if (isOwnershipChanged) {
					username = appRoleUpdate.getOwner();
					String appRoleUsermetadataJson = ControllerUtil.populateUserMetaJson(appRole, appRoleMetadataDetails.getCreatedBy());
					Response appRoleUserMetaDataDeletionResponse = reqProcessor.process("/delete", appRoleUsermetadataJson, token);
					if (appRoleUserMetaDataDeletionResponse.getHttpstatus().equals(HttpStatus.NO_CONTENT)) {
						log.debug(JSONUtil.getJSON(ImmutableMap.<String, String>builder().
								put(LogMessage.USER, ThreadLocalContext.getCurrentMap().get(LogMessage.USER)).
								put(LogMessage.ACTION, UPDATE_APPROLE).
								put(LogMessage.MESSAGE, String.format("Successfully deleted metadata for old AppRole owner [%s]",
										appRoleMetadataDetails.getCreatedBy())).
								put(LogMessage.APIURL, ThreadLocalContext.getCurrentMap().get(LogMessage.APIURL)).
								build()));

						if (appRoleUpdate.getNew_owner_email() != null) {
							sendTransferNotificationEmail(appRoleMetadataDetails.getCreatedBy(), appRole.getRole_name(),
									appRoleUpdate.getOwner(), appRoleUpdate.getNew_owner_email());
						}
					} else {
						log.error(JSONUtil.getJSON(ImmutableMap.<String, String>builder().
								put(LogMessage.USER, ThreadLocalContext.getCurrentMap().get(LogMessage.USER)).
								put(LogMessage.ACTION, UPDATE_APPROLE).
								put(LogMessage.MESSAGE, String.format("Error deleting metadata for old AppRole owner [%s]",
										appRoleMetadataDetails.getCreatedBy())).
								put(LogMessage.APIURL, ThreadLocalContext.getCurrentMap().get(LogMessage.APIURL)).
								build()));
					}
				}
				createAppRoleMetaData(token, appRole, username);
			}

			if (isSharedToChanged) {
				List<String> usersToBeRemovedFromSharedList = appRoleMetadataDetails.getSharedTo();
				if (!CollectionUtils.isEmpty(usersToBeRemovedFromSharedList)) {
					if (appRole.getShared_to() != null) {
						usersToBeRemovedFromSharedList.removeAll(appRole.getShared_to());
					}

					for (String userToBeRemoved : usersToBeRemovedFromSharedList) {
						if (!userToBeRemoved.equals(appRoleUpdate.getOwner())) {
							String path = TVaultConstants.APPROLE_USERS_METADATA_MOUNT_PATH + "/" + userToBeRemoved + "/" + appRole.getRole_name();
							Response deleteResponse = reqProcessor.process("/delete", "{\"path\":\"" + path + "\"}", token);
							if (HttpStatus.NO_CONTENT.equals(deleteResponse.getHttpstatus())) {
								log.debug(JSONUtil.getJSON(ImmutableMap.<String, String>builder().
										put(LogMessage.USER, ThreadLocalContext.getCurrentMap().get(LogMessage.USER)).
										put(LogMessage.ACTION, SSLCertificateConstants.DELETE_METADATA_PERMISSIONS).
										put(LogMessage.MESSAGE, String.format("Successfully deleted metadata for user [%s]", userToBeRemoved)).
										put(LogMessage.APIURL, ThreadLocalContext.getCurrentMap().get(LogMessage.APIURL)).
										build()));
							} else {
								log.error(JSONUtil.getJSON(ImmutableMap.<String, String>builder().
										put(LogMessage.USER, ThreadLocalContext.getCurrentMap().get(LogMessage.USER)).
										put(LogMessage.ACTION, SSLCertificateConstants.DELETE_METADATA_PERMISSIONS).
										put(LogMessage.MESSAGE, String.format("Failed to delete metadata for user [%s]", userToBeRemoved)).
										put(LogMessage.APIURL, ThreadLocalContext.getCurrentMap().get(LogMessage.APIURL)).
										build()));
								return ResponseEntity.status(HttpStatus.BAD_REQUEST).body(
										String.format("{\"errors\":[\"Failed to delete metadata for user %s\"]}", userToBeRemoved));
							}
						}
					}
				}
			}

			return ResponseEntity.status(HttpStatus.OK).body("{\"messages\":[\"AppRole updated successfully.\"]}");
		}
		log.error(JSONUtil.getJSON(ImmutableMap.<String, String>builder().
			      put(LogMessage.USER, ThreadLocalContext.getCurrentMap().get(LogMessage.USER)).
				  put(LogMessage.ACTION, UPDATE_APPROLE).
			      put(LogMessage.MESSAGE, "Update of AppRole failed").
			      put(LogMessage.RESPONSE, response.getResponse()).
			      put(LogMessage.STATUS, response.getHttpstatus().toString()).
			      put(LogMessage.APIURL, ThreadLocalContext.getCurrentMap().get(LogMessage.APIURL)).
			      build()));
		return ResponseEntity.status(response.getHttpstatus()).body(response.getResponse());
	}

	private void sendTransferNotificationEmail(String originalAppRoleOwner, String appRoleName, String newOwnerName, String ownerEmail) {
		DirectoryUser oldOwnerObj = commonUtils.getUserDetails(originalAppRoleOwner);
		if (oldOwnerObj != null && oldOwnerObj.getDisplayName() != null && oldOwnerObj.getDisplayName().trim().isEmpty()) {
			oldOwnerObj.setDisplayName(oldOwnerObj.getUserName());
		}
		DirectoryUser newOwnerObj = commonUtils.getUserDetails(newOwnerName);
		if (newOwnerObj != null && newOwnerObj.getDisplayName() != null && newOwnerObj.getDisplayName().trim().isEmpty()) {
			newOwnerObj.setDisplayName(newOwnerObj.getUserName());
		}
		Map<String, String> mailTemplateVariables = new HashMap<>();
		mailTemplateVariables.put("name", newOwnerObj != null ? newOwnerObj.getDisplayName() : "");
		mailTemplateVariables.put("appRoleName", appRoleName);
		mailTemplateVariables.put("oldOwnerName", oldOwnerObj != null ? oldOwnerObj.getDisplayName() : "");
		List<String> to = new ArrayList<>();
		to.add(ownerEmail);
		List<String> cc = new ArrayList<>();
		if (oldOwnerObj != null) {
			if (oldOwnerObj.getUserEmail() != null) {
				cc.add(oldOwnerObj.getUserEmail());
			}
		}
		String subject = String.format("AppRole %s has been successfully transferred", appRoleName);
		emailUtils.sendAppRoleHtmlEmalFromTemplate(supportEmail, to, cc, subject, mailTemplateVariables, "AppRoleTransferEmailTemplate");
	}

	private AppRole constructAppRoleFromUpdateObject(AppRoleUpdate appRoleUpdate) {
		AppRole appRole = new AppRole();
		appRole.setRole_name(appRoleUpdate.getRole_name());
		appRole.setPolicies(appRoleUpdate.getPolicies());
		appRole.setBind_secret_id(appRoleUpdate.isBind_secret_id());
		appRole.setSecret_id_num_uses(appRoleUpdate.getSecret_id_num_uses());
		appRole.setToken_num_uses(appRoleUpdate.getToken_num_uses());
		appRole.setToken_ttl(appRoleUpdate.getToken_ttl());
		appRole.setToken_max_ttl(appRoleUpdate.getToken_max_ttl());
		appRole.setShared_to(appRoleUpdate.getShared_to());

		return appRole;
	}

	private boolean validateNoSharedUserIsOwner(AppRoleMetadataDetails appRoleMetadataDetails, List<String> sharedUsers) {
		boolean isValid = true;
		if (!CollectionUtils.isEmpty(sharedUsers)) {
			for (String user : sharedUsers) {
				if (isAppRoleOwner(user, appRoleMetadataDetails)) {
					log.error(JSONUtil.getJSON(ImmutableMap.<String, String>builder().
						put(LogMessage.USER, ThreadLocalContext.getCurrentMap().get(LogMessage.USER)).
						put(LogMessage.ACTION, "validateNoSharedToUserIsOwner").
						put(LogMessage.MESSAGE, "Failed validation because a shared user is the owner").
						put(LogMessage.APIURL, ThreadLocalContext.getCurrentMap().get(LogMessage.APIURL)).
						build()));
					isValid = false;
					break;
				}
			}
		}
		return isValid;
	}

	/**
	 * Determines whether user is the creator of the approle
	 * @param username
	 * @param appRoleMetadataDetails
	 * @return boolean
	 */
	boolean isAppRoleOwner(String username, AppRoleMetadataDetails appRoleMetadataDetails) {
		if (appRoleMetadataDetails == null) {
			log.error(JSONUtil.getJSON(ImmutableMap.<String, String>builder().
					put(LogMessage.USER, ThreadLocalContext.getCurrentMap().get(LogMessage.USER)).
					put(LogMessage.ACTION, "isAppRoleOwner").
					put(LogMessage.MESSAGE, "Check to see if user is owner of approle failed because appRoleMetadataDetails was null").
					put(LogMessage.APIURL, ThreadLocalContext.getCurrentMap().get(LogMessage.APIURL)).
					build()));
			return false;
		}
		return appRoleMetadataDetails.getCreatedBy().equals(username);
	}

	/**
	 * Determines whether the sharedTo list has changed. <br>
	 * If the sharedTo list is null then we assume the user doesn't want to make a change to the field, <br>
	 * so false is returned in that scenario.
	 *
	 * @param appRoleMetadataDetails
	 * @param newSharedTo
	 * @return boolean
	 */
	private boolean isSharedToChanged(AppRoleMetadataDetails appRoleMetadataDetails, List<String> newSharedTo) {
		if (appRoleMetadataDetails == null) {
			log.error(JSONUtil.getJSON(ImmutableMap.<String, String>builder().
				put(LogMessage.USER, ThreadLocalContext.getCurrentMap().get(LogMessage.USER)).
				put(LogMessage.ACTION, "isSharedToChanged").
				put(LogMessage.MESSAGE, "Check to see if sharedTo array changed failed because appRoleMetadataDetails was null").
				put(LogMessage.APIURL, ThreadLocalContext.getCurrentMap().get(LogMessage.APIURL)).
				build()));
			return false;
		}
		if (newSharedTo == null) {
			return false;
		}
		List<String> oldSharedTo = appRoleMetadataDetails.getSharedTo();
		if (CollectionUtils.isEmpty(oldSharedTo)) {
			return !CollectionUtils.isEmpty(newSharedTo);
		}
		if (CollectionUtils.isEmpty(newSharedTo)) {
			return true;
		}
		return !(oldSharedTo.containsAll(newSharedTo) && newSharedTo.containsAll(oldSharedTo));
	}

	/**
	 * Configure approle
	 * @param rolename
	 * @param policies
	 * @param token
	 * @return
	 */
	public Response configureApprole(String rolename,String policies,String token ){
		log.debug(JSONUtil.getJSON(ImmutableMap.<String, String>builder().
				put(LogMessage.USER, ThreadLocalContext.getCurrentMap().get(LogMessage.USER)).
				put(LogMessage.ACTION, "configureApprole").
				put(LogMessage.MESSAGE, "Trying to create approleConfig json with rolename and policies.").
				put(LogMessage.APIURL, ThreadLocalContext.getCurrentMap().get(LogMessage.APIURL)).
				build()));
		ObjectMapper objMapper = new ObjectMapper();
		Map<String,String>configureUserMap = new HashMap<>();
		configureUserMap.put("role_name", rolename);
		configureUserMap.put(POLICIESSTR, policies);
		String approleConfigJson =TVaultConstants.EMPTY;

		try {
			approleConfigJson = objMapper.writeValueAsString(configureUserMap);
			log.debug(JSONUtil.getJSON(ImmutableMap.<String, String>builder().
					put(LogMessage.USER, ThreadLocalContext.getCurrentMap().get(LogMessage.USER)).
					put(LogMessage.ACTION, "configureApprole").
					put(LogMessage.MESSAGE, "Able to create approleConfig json with rolename and policies.").
					put(LogMessage.APIURL, ThreadLocalContext.getCurrentMap().get(LogMessage.APIURL)).
					build()));
		} catch (JsonProcessingException e) {
			log.error(e);
			log.error(JSONUtil.getJSON(ImmutableMap.<String, String>builder().
					put(LogMessage.USER, ThreadLocalContext.getCurrentMap().get(LogMessage.USER)).
					put(LogMessage.ACTION, "configureApprole").
					put(LogMessage.MESSAGE, String.format ("Unable to create approleConfigJson  [%s] with rolename [%s] policies [%s] ", e.getMessage(), rolename, policies)).
					put(LogMessage.APIURL, ThreadLocalContext.getCurrentMap().get(LogMessage.APIURL)).
					build()));
		}
		return reqProcessor.process(CREATEPATH,approleConfigJson,token);
	}

	/**
	 * Retrieves the list of entities that are associated to this AppRole.
	 * Entities include safes, services accounts, and certs.
	 * @param roleName - The name of the AppRole to get the list of associations for
	 * @param token
	 * @return ResponseEntity
	 */
	public ResponseEntity<String> listAppRoleEntityAssociations(String roleName, String token) {
		Response readResponse = reqProcessor.process(READPATH,ROLENAMESTR + roleName + "\"}",token);
		Set<String> safes = new HashSet<>();
		Set<String> iamSvcAccs = new HashSet<>();
		Set<String> adSvcAccs = new HashSet<>();
		Set<String> azureSvcAccs = new HashSet<>();
		Set<String> certs = new HashSet<>();
		if (HttpStatus.OK.equals(readResponse.getHttpstatus())) {
			log.debug(JSONUtil.getJSON(ImmutableMap.<String, String>builder().
				put(LogMessage.USER, ThreadLocalContext.getCurrentMap().get(LogMessage.USER)).
				put(LogMessage.ACTION, READ_APPROLE).
				put(LogMessage.MESSAGE, READCOMPLETESTR).
				put(LogMessage.STATUS, readResponse.getHttpstatus().toString()).
				put(LogMessage.APIURL, ThreadLocalContext.getCurrentMap().get(LogMessage.APIURL)).
				build()));

			Set<String>[] entityResponse = getEntityAssociationsFromResponse(readResponse, roleName, safes,
					iamSvcAccs, adSvcAccs, azureSvcAccs, certs);

			if (entityResponse == null) {
				return ResponseEntity.status(HttpStatus.NOT_FOUND).body(APPROLENONEXISTSTR);
			} else {
				safes = entityResponse[0];
				iamSvcAccs = entityResponse[1];
				adSvcAccs = entityResponse[2];
				azureSvcAccs = entityResponse[3];
				certs = entityResponse[4];
			}
		} else if (HttpStatus.NOT_FOUND.equals(readResponse.getHttpstatus())) {
			log.error(JSONUtil.getJSON(ImmutableMap.<String, String>builder().
				put(LogMessage.USER, ThreadLocalContext.getCurrentMap().get(LogMessage.USER)).
				put(LogMessage.ACTION, READ_APPROLE).
				put(LogMessage.MESSAGE, READCOMPLETESTR).
				put(LogMessage.STATUS, readResponse.getHttpstatus().toString()).
				put(LogMessage.APIURL, ThreadLocalContext.getCurrentMap().get(LogMessage.APIURL)).
				build()));
			return ResponseEntity.status(HttpStatus.NOT_FOUND).body(APPROLENONEXISTSTR);
		}
		return ResponseEntity.status(HttpStatus.OK).body("{\"messages\":[{\"safes\":\"" + safes + "\"}," +
				"{\"iamsvcaccs\":\"" + iamSvcAccs + "\"},{\"adsvcaccs\":\"" + adSvcAccs +"\"},{\"azuresvcaccs\":\"" + azureSvcAccs + "\"}," +
				"{\"certs\":\"" + certs + "\"}]}");
	}

	/**
	 * Helper method to parse out array of entities from the AppRole read response.
	 * Includes safes, service accounts, and certs associated to the AppRole.
	 * @param readResponse - The response obtained by reading the AppRole
	 * @param roleName - The name of the AppRole
	 * @param safes
	 * @param iamSvcAccs
	 * @param adSvcAccs
	 * @param azureSvcAccs
	 * @param certs
	 * @return Set
	 */
	private Set<String>[] getEntityAssociationsFromResponse(Response readResponse, String roleName,
							Set<String> safes, Set<String> iamSvcAccs, Set<String> adSvcAccs, Set<String> azureSvcAccs, Set<String> certs) {
		Map<String, Object> responseMap = ControllerUtil.parseJson(readResponse.getResponse());

		if (responseMap.isEmpty()) {
			log.error(JSONUtil.getJSON(ImmutableMap.<String, String>builder().
				put(LogMessage.USER, ThreadLocalContext.getCurrentMap().get(LogMessage.USER)).
				put(LogMessage.ACTION, READROLEID).
				put(LogMessage.MESSAGE, String.format("Reading details for AppRole [%s] failed.", roleName)).
				put(LogMessage.APIURL, ThreadLocalContext.getCurrentMap().get(LogMessage.APIURL)).
				build()));
			return null;
		}

		Map<String, Object> responseDataMap = (Map<String, Object>) responseMap.get("data");
		if (!responseDataMap.isEmpty()) {
			List<String> policies = (ArrayList<String>) responseDataMap.get("policies");
			if (CollectionUtils.isNotEmpty(policies)) {
				for (String policy : policies) {
					if (policy.startsWith(TVaultConstants.USERS, 2)
							|| policy.startsWith(TVaultConstants.SHARED, 2)
							|| policy.startsWith(TVaultConstants.APPS, 2)) {
						safes.add(getPartOfStringAfterCertainCharacter(policy, 2, '_'));
					} else if (policy.startsWith(TVaultConstants.IAM_SVC_ACC_PATH_PREFIX, 2)) {
						iamSvcAccs.add(getPartOfStringAfterCertainCharacter(policy, 3, '_'));
					} else if (policy.startsWith(TVaultConstants.SVC_ACC_PATH_PREFIX, 2)) {
						adSvcAccs.add(getPartOfStringAfterCertainCharacter(policy, 2, '_'));
					} else if (policy.startsWith(TVaultConstants.AZURE_SVC_ACC_PREFIX, 2)) {
						azureSvcAccs.add(getPartOfStringAfterCertainCharacter(policy, 2, '_'));
					} else if (policy.startsWith(TVaultConstants.CERT_POLICY_PREFIX, 2)) {
						certs.add(getPartOfStringAfterCertainCharacter(policy, 2, '_'));
					}
				}
			} else {
				log.warn(JSONUtil.getJSON(ImmutableMap.<String, String>builder().
					put(LogMessage.USER, ThreadLocalContext.getCurrentMap().get(LogMessage.USER)).
					put(LogMessage.ACTION, READROLEID).
					put(LogMessage.MESSAGE, String.format("No policies were found for AppRole [%s]", roleName)).
					put(LogMessage.APIURL, ThreadLocalContext.getCurrentMap().get(LogMessage.APIURL)).
					build()));
			}
		} else {
			log.error(JSONUtil.getJSON(ImmutableMap.<String, String>builder().
				put(LogMessage.USER, ThreadLocalContext.getCurrentMap().get(LogMessage.USER)).
				put(LogMessage.ACTION, READROLEID).
				put(LogMessage.MESSAGE, String.format("Response map was empty for AppRole [%s]", roleName)).
				put(LogMessage.APIURL, ThreadLocalContext.getCurrentMap().get(LogMessage.APIURL)).
				build()));
			return null;
		}

		return new Set[] { safes, iamSvcAccs, adSvcAccs, azureSvcAccs, certs };
	}

	/**
	 * Calls recursive method to get the part of a String after n instances of a given character.<br><br>
	 * Ex: For the String "this_is_a_test" with nOccurencesToSkip = 2 and charToSkip = '_' it returns
	 * "a_test" because that's the part of the String following the second '_' character.
	 * @return String
	 */
	private String getPartOfStringAfterCertainCharacter(String str, int nOccurrencesToSkip, char charToSkip) {
		int indexAtNthOccurence = getNthIndexOfGivenCharacterInString(str, nOccurrencesToSkip, charToSkip, 0);
		return str.substring(indexAtNthOccurence + 1);
	}

	private int getNthIndexOfGivenCharacterInString(String str, int nOccurrencesToSkip, char charToSkip, int startingIndex) {
		if (nOccurrencesToSkip == 1) {
			return str.indexOf(charToSkip) + startingIndex;
		} else {
			return getNthIndexOfGivenCharacterInString(str.substring(str.indexOf(charToSkip) + 1),
					nOccurrencesToSkip - 1, charToSkip, startingIndex + str.indexOf(charToSkip) + 1);
		}
	}
}
