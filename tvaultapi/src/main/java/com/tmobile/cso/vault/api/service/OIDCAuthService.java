package com.tmobile.cso.vault.api.service;

import com.fasterxml.jackson.core.type.TypeReference;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.google.gson.JsonArray;
import com.google.gson.JsonObject;
import com.google.gson.JsonParser;
import com.tmobile.cso.vault.api.common.TVaultConstants;
import com.tmobile.cso.vault.api.controller.ControllerUtil;
import com.tmobile.cso.vault.api.controller.OIDCUtil;
import com.tmobile.cso.vault.api.model.*;
import com.tmobile.cso.vault.api.utils.TokenUtils;
import org.apache.http.HttpResponse;
import org.apache.http.NameValuePair;
import org.apache.http.client.HttpClient;
import org.apache.http.client.entity.UrlEncodedFormEntity;
import org.apache.http.client.methods.HttpGet;
import org.apache.http.client.methods.HttpPost;
import org.apache.http.conn.ssl.NoopHostnameVerifier;
import org.apache.http.impl.client.HttpClientBuilder;
import org.apache.http.impl.client.LaxRedirectStrategy;
import org.apache.http.message.BasicNameValuePair;
import org.apache.http.ssl.SSLContextBuilder;
import org.apache.http.ssl.TrustStrategy;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.stereotype.Component;

import com.google.common.collect.ImmutableMap;
import com.tmobile.cso.vault.api.exception.LogMessage;
import com.tmobile.cso.vault.api.process.RequestProcessor;
import com.tmobile.cso.vault.api.process.Response;
import com.tmobile.cso.vault.api.utils.JSONUtil;
import com.tmobile.cso.vault.api.utils.ThreadLocalContext;
import org.springframework.util.StringUtils;

import java.io.BufferedReader;
import java.io.IOException;
import java.io.InputStreamReader;
import java.io.UnsupportedEncodingException;
import java.security.KeyManagementException;
import java.security.KeyStoreException;
import java.security.NoSuchAlgorithmException;
import java.security.cert.CertificateException;
import java.security.cert.X509Certificate;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

@Component
public class OIDCAuthService {

    @Autowired
    private RequestProcessor reqProcessor;

    @Value("${selfservice.enable}")
    private boolean isSSEnabled;

    @Value("${ad.passwordrotation.enable}")
    private boolean isAdPswdRotationEnabled;

    @Value("${sso.azure.resourceendpoint}")
    private String ssoResourceEndpoint;

    @Value("${sso.azure.groupsendpoint}")
    private String ssoGroupsEndpoint;

    private static Logger log = LogManager.getLogger(OIDCAuthService.class);

	/**
	 * Get Authentication Mounts
	 *
	 * @param token
	 * @return
	 */
	public ResponseEntity<String> getAuthenticationMounts(String token) {
		log.debug(JSONUtil.getJSON(ImmutableMap.<String, String>builder()
				.put(LogMessage.USER, ThreadLocalContext.getCurrentMap().get(LogMessage.USER))
				.put(LogMessage.ACTION, "List Auth Methods").put(LogMessage.MESSAGE, "Trying to get all auth Methods")
				.put(LogMessage.APIURL, ThreadLocalContext.getCurrentMap().get(LogMessage.APIURL)).build()));

		String mountAccessor = OIDCUtil.fetchMountAccessorForOidc(token);
		return ResponseEntity.status(HttpStatus.OK).body(mountAccessor);
	}
    /**
     * Entity Lookup from identity engine
     * @param token
     * @param oidcLookupEntityRequest
     * @return
     */
	public ResponseEntity<OIDCEntityResponse> entityLookUp(String token,
			OIDCLookupEntityRequest oidcLookupEntityRequest) {
		log.debug(JSONUtil.getJSON(ImmutableMap.<String, String>builder()
				.put(LogMessage.USER, ThreadLocalContext.getCurrentMap().get(LogMessage.USER))
				.put(LogMessage.ACTION, "Entity Lookup from identity engine")
				.put(LogMessage.MESSAGE, "Trying to Lookup entity from identity engine")
				.put(LogMessage.APIURL, ThreadLocalContext.getCurrentMap().get(LogMessage.APIURL)).build()));
		OIDCEntityResponse oidcEntityResponse = new OIDCEntityResponse();
		String jsonStr = JSONUtil.getJSON(oidcLookupEntityRequest);
		Response response = reqProcessor.process("/identity/lookup/entity", jsonStr, token);
		if (response.getHttpstatus().equals(HttpStatus.OK)) {
			oidcEntityResponse = OIDCUtil.getEntityLookUpResponse(response.getResponse());
			log.debug(JSONUtil.getJSON(ImmutableMap.<String, String>builder()
					.put(LogMessage.USER, ThreadLocalContext.getCurrentMap().get(LogMessage.USER))
					.put(LogMessage.ACTION, "entityLookUp")
					.put(LogMessage.MESSAGE, "Successfully received entity lookup")
					.put(LogMessage.STATUS, response.getHttpstatus().toString())
					.put(LogMessage.APIURL, ThreadLocalContext.getCurrentMap().get(LogMessage.APIURL)).build()));
			return ResponseEntity.status(response.getHttpstatus()).body(oidcEntityResponse);
		} else {
			log.error(JSONUtil.getJSON(ImmutableMap.<String, String>builder().
					put(LogMessage.USER, ThreadLocalContext.getCurrentMap().get(LogMessage.USER)).
					put(LogMessage.ACTION, "entityLookUp").
					put(LogMessage.MESSAGE, "Failed entity Lookup").
					put(LogMessage.STATUS, response.getHttpstatus().toString()).
					put(LogMessage.APIURL, ThreadLocalContext.getCurrentMap().get(LogMessage.APIURL)).
					build()));
			return ResponseEntity.status(response.getHttpstatus()).body(oidcEntityResponse);

		}
	}
    /**
     * Group Entity Lookup from identity engine
     * @param token
     * @param oidcLookupEntityRequest
     * @return
     */
    public ResponseEntity<String> groupEntityLookUp(String token, OIDCLookupEntityRequest oidcLookupEntityRequest) {
        log.debug(JSONUtil.getJSON(ImmutableMap.<String, String> builder()
                .put(LogMessage.USER, ThreadLocalContext.getCurrentMap().get(LogMessage.USER))
                .put(LogMessage.ACTION, "Group Entity Lookup from identity engine").put(LogMessage.MESSAGE, "Trying to Lookup group entity from identity engine")
                .put(LogMessage.APIURL, ThreadLocalContext.getCurrentMap().get(LogMessage.APIURL)).build()));

        String jsonStr = JSONUtil.getJSON(oidcLookupEntityRequest);
        Response response = reqProcessor.process("/identity/lookup/group", jsonStr, token);
        return ResponseEntity.status(response.getHttpstatus()).body(response.getResponse());
    }
    /**
     * Read Entity Alias By ID
     * @param token
     * @param id
     * @return
     */
    public ResponseEntity<String> readEntityAliasById(String token, String id) {
        log.debug(
                JSONUtil.getJSON(
                        ImmutableMap.<String, String> builder()
                                .put(LogMessage.USER,
                                        ThreadLocalContext.getCurrentMap().get(LogMessage.USER))
                                .put(LogMessage.ACTION, "Read Entity Alias By ID")
                                .put(LogMessage.MESSAGE, "Trying to read Entity Alias").put(LogMessage.APIURL,
                                ThreadLocalContext.getCurrentMap().get(LogMessage.APIURL))
                                .build()));
        Response response = reqProcessor.process("/identity/entity-alias/id", "{\"id\":\"" + id + "\"}", token);
        return ResponseEntity.status(response.getHttpstatus()).body(response.getResponse());
    }
    /**
     * Read Entity By Name
     * @param token
     * @param entityName
     * @return
     */
    public ResponseEntity<String> readEntityByName(String token, String entityName) {
        log.debug(
                JSONUtil.getJSON(
                        ImmutableMap.<String, String> builder()
                                .put(LogMessage.USER,
                                        ThreadLocalContext.getCurrentMap().get(LogMessage.USER))
                                .put(LogMessage.ACTION, "Read Entity By Name")
                                .put(LogMessage.MESSAGE, "Trying to read Entity").put(LogMessage.APIURL,
                                ThreadLocalContext.getCurrentMap().get(LogMessage.APIURL))
                                .build()));
        Response response = reqProcessor.process("/identity/entity/name", "{\"name\":\"" + entityName + "\"}", token);
        return ResponseEntity.status(response.getHttpstatus()).body(response.getResponse());
    }

    /**
     * Update Entity By Name
     * @param token
     * @param oidcEntityRequest
     * @return
     */
	public ResponseEntity<String> updateEntityByName(String token, OIDCEntityRequest oidcEntityRequest) {
		log.debug(JSONUtil.getJSON(ImmutableMap.<String, String>builder()
				.put(LogMessage.USER, ThreadLocalContext.getCurrentMap().get(LogMessage.USER))
				.put(LogMessage.ACTION, "Update Entity By Name")
				.put(LogMessage.MESSAGE, "Trying to update entity by name")
				.put(LogMessage.APIURL, ThreadLocalContext.getCurrentMap().get(LogMessage.APIURL)).build()));

		String jsonStr = JSONUtil.getJSON(oidcEntityRequest);
		Response response = reqProcessor.process("/identity/entity/name/update", jsonStr, token);
		return ResponseEntity.status(response.getHttpstatus()).body(response.getResponse());
	}

    /**
     * Update Identity Group By Name
     * @param token
     * @param oidcIdentityGroupRequest
     * @return
     */
    public ResponseEntity<String> updateIdentityGroupByName(String token,
                                                            OIDCIdentityGroupRequest oidcIdentityGroupRequest) {
        log.debug(JSONUtil.getJSON(ImmutableMap.<String, String> builder()
                .put(LogMessage.USER, ThreadLocalContext.getCurrentMap().get(LogMessage.USER))
                .put(LogMessage.ACTION, "Update Identity Group By Name")
                .put(LogMessage.MESSAGE, "Trying to update identity group entity by name")
                .put(LogMessage.APIURL, ThreadLocalContext.getCurrentMap().get(LogMessage.APIURL)).build()));

        String jsonStr = JSONUtil.getJSON(oidcIdentityGroupRequest);
        Response response = reqProcessor.process("/identity/group/name/update", jsonStr, token);
        return ResponseEntity.status(response.getHttpstatus()).body(response.getResponse());
    }

    /**
     * Group Alias By Id
     * @param token
     * @param id
     * @return
     */
    public ResponseEntity<String> readGroupAliasById(String token, String id) {
        log.debug(
                JSONUtil.getJSON(
                        ImmutableMap.<String, String> builder()
                                .put(LogMessage.USER,
                                        ThreadLocalContext.getCurrentMap().get(LogMessage.USER))
                                .put(LogMessage.ACTION, "Read Group Alias By Id")
                                .put(LogMessage.MESSAGE, "Trying to get Group Alias By Id").put(LogMessage.APIURL,
                                ThreadLocalContext.getCurrentMap().get(LogMessage.APIURL))
                                .build()));
        Response response = reqProcessor.process("/identity/group-alias/id", "{\"id\":\"" + id + "\"}", token);
        return ResponseEntity.status(response.getHttpstatus()).body(response.getResponse());
    }

    /**
     * Read Group Alias By Id
     * @param token
     * @param name
     * @return
     */
    public ResponseEntity<String> deleteGroupByName(String token, String name) {
        log.debug(
                JSONUtil.getJSON(
                        ImmutableMap.<String, String> builder()
                                .put(LogMessage.USER,
                                        ThreadLocalContext.getCurrentMap().get(LogMessage.USER))
                                .put(LogMessage.ACTION, "Read Group Alias By Id")
                                .put(LogMessage.MESSAGE, "Trying to read Group Alias By Id").put(LogMessage.APIURL,
                                ThreadLocalContext.getCurrentMap().get(LogMessage.APIURL))
                                .build()));
        Response response = reqProcessor.process("/identity/group/name", "{\"name\":\"" + name + "\"}", token);
        return ResponseEntity.status(response.getHttpstatus()).body(response.getResponse());
    }

    /**
     * Delete Group Alias By Id
     * @param token
     * @param id
     * @return
     */
    public ResponseEntity<String> deleteGroupAliasByID(String token, String id) {
        log.debug(
                JSONUtil.getJSON(
                        ImmutableMap.<String, String> builder()
                                .put(LogMessage.USER,
                                        ThreadLocalContext.getCurrentMap().get(LogMessage.USER))
                                .put(LogMessage.ACTION, "Delete group alias By Id")
                                .put(LogMessage.MESSAGE, "Trying to read Group Alias By Id").put(LogMessage.APIURL,
                                ThreadLocalContext.getCurrentMap().get(LogMessage.APIURL))
                                .build()));
        Response response = reqProcessor.process("/identity/group-alias/id", "{\"id\":\"" + id + "\"}", token);
        return ResponseEntity.status(response.getHttpstatus()).body(response.getResponse());
    }

    /**
     * Create Group Alias
     * @param token
     * @param groupAliasRequest
     * @return
     */
    public ResponseEntity<String> createGroupAlias(String token, GroupAliasRequest groupAliasRequest) {
        log.debug(
                JSONUtil.getJSON(
                        ImmutableMap.<String, String> builder()
                                .put(LogMessage.USER,
                                        ThreadLocalContext.getCurrentMap().get(LogMessage.USER))
                                .put(LogMessage.ACTION, "Create Group Alias")
                                .put(LogMessage.MESSAGE, "Trying to create Group Alias").put(LogMessage.APIURL,
                                ThreadLocalContext.getCurrentMap().get(LogMessage.APIURL))
                                .build()));
        String jsonStr = JSONUtil.getJSON(groupAliasRequest);
        Response response = reqProcessor.process("/identity/group-alias", jsonStr, token);
        return ResponseEntity.status(response.getHttpstatus()).body(response.getResponse());
    }

    /**
     * To get OIDC auth url.
     * @param oidcRequest
     * @return
     */
    public ResponseEntity<String> getAuthUrl(OidcRequest oidcRequest) {
        String jsonStr = JSONUtil.getJSON(oidcRequest);
        Response response = reqProcessor.process("/auth/oidc/oidc/auth_url",jsonStr, "");
        if(HttpStatus.OK.equals(response.getHttpstatus())){
            log.info(JSONUtil.getJSON(ImmutableMap.<String, String>builder().
                    put(LogMessage.USER, ThreadLocalContext.getCurrentMap().get(LogMessage.USER)).
                    put(LogMessage.ACTION, "getAuthUrl").
                    put(LogMessage.MESSAGE, "Successfully retrieved OIDC auth url").
                    put(LogMessage.APIURL, ThreadLocalContext.getCurrentMap().get(LogMessage.APIURL)).
                    build()));
            return ResponseEntity.status(response.getHttpstatus()).body(response.getResponse());
        }else{
            log.error(JSONUtil.getJSON(ImmutableMap.<String, String>builder().
                    put(LogMessage.USER, ThreadLocalContext.getCurrentMap().get(LogMessage.USER)).
                    put(LogMessage.ACTION, "getAuthUrl").
                    put(LogMessage.MESSAGE, String.format ("Failed to get OIDC auth url [%s]", response.getResponse())).
                    put(LogMessage.APIURL, ThreadLocalContext.getCurrentMap().get(LogMessage.APIURL)).
                    build()));
            return ResponseEntity.status(response.getHttpstatus()).body("{\"errors\":[\"Failed to get OIDC auth url\"]}");
        }
    }

    /**
     * To get vault token with OIDC callback state and code.
     * @param state
     * @param code
     * @return
     */
    public ResponseEntity<String> processOIDCCallback(String state, String code) {

        String pathStr = "?code="+code+"&state="+state;
        Response response = reqProcessor.process("/auth/oidc/oidc/callback","{\"path\":\""+pathStr+"\"}", "");
        if(HttpStatus.OK.equals(response.getHttpstatus())){
            Map<String, Object> responseMap = null;
            try {
                responseMap = new ObjectMapper().readValue(response.getResponse(), new TypeReference<Map<String, Object>>(){});
            } catch (IOException e) {
                log.error(JSONUtil.getJSON(ImmutableMap.<String, String>builder().
                        put(LogMessage.USER, ThreadLocalContext.getCurrentMap().get(LogMessage.USER)).
                        put(LogMessage.ACTION, "processCallback").
                        put(LogMessage.MESSAGE, "Failed to getresponse map from callback response").
                        put(LogMessage.APIURL, ThreadLocalContext.getCurrentMap().get(LogMessage.APIURL)).
                        build()));
            }
            if(responseMap!=null && responseMap.get("access")!=null) {
                Map<String,Object> access = (Map<String,Object>)responseMap.get("access");
                access = ControllerUtil.filterDuplicateSafePermissions(access);
                access = ControllerUtil.filterDuplicateSvcaccPermissions(access);
                responseMap.put("access", access);
                // set SS, AD password rotation enable status
                Map<String,Object> feature = new HashMap<>();
                feature.put(TVaultConstants.SELFSERVICE, isSSEnabled);
                feature.put(TVaultConstants.ADAUTOROTATION, isAdPswdRotationEnabled);
                responseMap.put("feature", feature);
                response.setResponse(JSONUtil.getJSON(responseMap));
            }

            log.info(JSONUtil.getJSON(ImmutableMap.<String, String>builder().
                    put(LogMessage.USER, ThreadLocalContext.getCurrentMap().get(LogMessage.USER)).
                    put(LogMessage.ACTION, "processCallback").
                    put(LogMessage.MESSAGE, "Successfully retrieved token from OIDC login").
                    put(LogMessage.APIURL, ThreadLocalContext.getCurrentMap().get(LogMessage.APIURL)).
                    build()));
            return ResponseEntity.status(response.getHttpstatus()).body(response.getResponse());
        }
        log.error(JSONUtil.getJSON(ImmutableMap.<String, String>builder().
                put(LogMessage.USER, ThreadLocalContext.getCurrentMap().get(LogMessage.USER)).
                put(LogMessage.ACTION, "processCallback").
                put(LogMessage.MESSAGE, "Failed to get token from OIDC login").
                put(LogMessage.APIURL, ThreadLocalContext.getCurrentMap().get(LogMessage.APIURL)).
                build()));
        return ResponseEntity.status(response.getHttpstatus()).body(response.getResponse());
    }

    /**
     * To get group object id from Azure AD.
     * @param groupName
     * @return
     */
    public ResponseEntity<String> getGroupObjectIdFromAzure(String groupName) {
        String ssoToken = getSSOToken();
        if (!StringUtils.isEmpty(ssoToken)) {
            String objectId = getGroupObjectResponse(ssoToken, groupName);
            if (objectId != null) {
                return ResponseEntity.status(HttpStatus.OK).body("{\"data\":{\"objectId\": \""+objectId+"\"}}");
            }
            return ResponseEntity.status(HttpStatus.NOT_FOUND).body("{\"errors\":[\"Group not found in Active Directory\"]}");
        }
        return ResponseEntity.status(HttpStatus.BAD_REQUEST).body("{\"errors\":[\"Failed to get SSO token for Azure AD access\"]}");
    }


    /**
     * To get object id for a group.
     *
     * @param ssoToken
     * @param groupName
     * @return
     */
    private String getGroupObjectResponse(String ssoToken, String groupName)  {
        JsonParser jsonParser = new JsonParser();
        HttpClient httpClient =null;
        String groupObjectId = null;
        try {
            httpClient = HttpClientBuilder.create().setSSLHostnameVerifier(
                    NoopHostnameVerifier.INSTANCE).
                    setSSLContext(
                            new SSLContextBuilder().loadTrustMaterial(null,new TrustStrategy() {
                                @Override
                                public boolean isTrusted(X509Certificate[] arg0, String arg1) throws CertificateException {
                                    return true;
                                }
                            }).build()
                    ).setRedirectStrategy(new LaxRedirectStrategy()).build();


        } catch (KeyManagementException | NoSuchAlgorithmException | KeyStoreException e1) {
            log.error(JSONUtil.getJSON(ImmutableMap.<String, String>builder().
                    put(LogMessage.USER, ThreadLocalContext.getCurrentMap().get(LogMessage.USER)).
                    put(LogMessage.ACTION, "getGroupObjectResponse").
                    put(LogMessage.MESSAGE, "Failed to initialize httpClient").
                    put(LogMessage.APIURL, ThreadLocalContext.getCurrentMap().get(LogMessage.APIURL)).
                    build()));
            return null;
        }

        String filterSearch = "$filter=displayName%20eq%20'"+groupName+"'";
        String api = ssoGroupsEndpoint + filterSearch;
        HttpGet getRequest = new HttpGet(api);
        getRequest.addHeader("accept", TVaultConstants.HTTP_CONTENT_TYPE_JSON);
        getRequest.addHeader("Authorization", "Bearer " + ssoToken);
        String output = "";
        StringBuilder jsonResponse = new StringBuilder();

        try {
            HttpResponse apiResponse = httpClient.execute(getRequest);
            if (apiResponse.getStatusLine().getStatusCode() != 200) {
                return null;
            }
            BufferedReader br = new BufferedReader(new InputStreamReader((apiResponse.getEntity().getContent())));
            while ((output = br.readLine()) != null) {
                jsonResponse.append(output);
            }

            JsonObject responseJson = (JsonObject) jsonParser.parse(jsonResponse.toString());
            if (responseJson != null && responseJson.has("value")) {
                JsonArray vaulesArray = responseJson.get("value").getAsJsonArray();
                if (vaulesArray.size() > 0) {
                    groupObjectId = vaulesArray.get(0).getAsJsonObject().get("id").getAsString();
                }
            }
            return groupObjectId;
        } catch (IOException e) {
            log.error(JSONUtil.getJSON(ImmutableMap.<String, String>builder().
                    put(LogMessage.USER, ThreadLocalContext.getCurrentMap().get(LogMessage.USER)).
                    put(LogMessage.ACTION, "getGroupObjectResponse").
                    put(LogMessage.MESSAGE, String.format ("Failed to parse group object api response")).
                    put(LogMessage.APIURL, ThreadLocalContext.getCurrentMap().get(LogMessage.APIURL)).
                    build()));
        }
        return null;
    }

    /**
     * To get SSO token.
     * @return
     */
    private String getSSOToken() {
        JsonParser jsonParser = new JsonParser();
        HttpClient httpClient;
        String accessToken = "";
        try {
            httpClient = HttpClientBuilder.create().setSSLHostnameVerifier(
                    NoopHostnameVerifier.INSTANCE).
                    setSSLContext(
                            new SSLContextBuilder().loadTrustMaterial(null, new TrustStrategy() {
                                @Override
                                public boolean isTrusted(X509Certificate[] arg0, String arg1) throws CertificateException {
                                    return true;
                                }
                            }).build()
                    ).setRedirectStrategy(new LaxRedirectStrategy()).build();
        } catch (KeyManagementException | NoSuchAlgorithmException | KeyStoreException e1) {
            log.error(JSONUtil.getJSON(ImmutableMap.<String, String>builder().
                    put(LogMessage.USER, ThreadLocalContext.getCurrentMap().get(LogMessage.USER)).
                    put(LogMessage.ACTION, "getSSOToken").
                    put(LogMessage.MESSAGE, "Failed to initialize httpClient").
                    put(LogMessage.APIURL, ThreadLocalContext.getCurrentMap().get(LogMessage.APIURL)).
                    build()));
            return null;
        }

        String api = ControllerUtil.getOidcADLoginUrl();
        HttpPost postRequest = new HttpPost(api);
        postRequest.addHeader("Content-type", TVaultConstants.HTTP_CONTENT_TYPE_URL_ENCODED);
        postRequest.addHeader("Accept",TVaultConstants.HTTP_CONTENT_TYPE_JSON);

        List<NameValuePair> form = new ArrayList<>();
        form.add(new BasicNameValuePair("grant_type", "client_credentials"));
        form.add(new BasicNameValuePair("client_id",  ControllerUtil.getOidcClientId()));
        form.add(new BasicNameValuePair("client_secret",  ControllerUtil.getOidcClientSecret()));
        form.add(new BasicNameValuePair("resource",  ssoResourceEndpoint));
        UrlEncodedFormEntity entity;

        try {
            entity = new UrlEncodedFormEntity(form);
        } catch (UnsupportedEncodingException e) {
            log.error(JSONUtil.getJSON(ImmutableMap.<String, String>builder().
                    put(LogMessage.USER, ThreadLocalContext.getCurrentMap().get(LogMessage.USER)).
                    put(LogMessage.ACTION, "getSSOToken").
                    put(LogMessage.MESSAGE, "Failed to encode entity").
                    put(LogMessage.APIURL, ThreadLocalContext.getCurrentMap().get(LogMessage.APIURL)).
                    build()));
            return null;
        }

        postRequest.setEntity(entity);
        String output;
        StringBuilder jsonResponse = new StringBuilder();

        try {
            HttpResponse apiResponse = httpClient.execute(postRequest);
            if (apiResponse.getStatusLine().getStatusCode() != 200) {
                log.error(JSONUtil.getJSON(ImmutableMap.<String, String>builder().
                        put(LogMessage.USER, ThreadLocalContext.getCurrentMap().get(LogMessage.USER)).
                        put(LogMessage.ACTION, "getSSOToken").
                        put(LogMessage.MESSAGE, "Failed to get sso token").
                        put(LogMessage.APIURL, ThreadLocalContext.getCurrentMap().get(LogMessage.APIURL)).
                        build()));
                return null;
            }
            BufferedReader br = new BufferedReader(new InputStreamReader((apiResponse.getEntity().getContent())));
            while ((output = br.readLine()) != null) {
                jsonResponse.append(output);
            }
            JsonObject responseJson = (JsonObject) jsonParser.parse(jsonResponse.toString());
            if (!responseJson.isJsonNull() && responseJson.has("access_token")) {
                accessToken = responseJson.get("access_token").getAsString();
            }
            return accessToken;
        } catch (IOException e) {
            log.error(JSONUtil.getJSON(ImmutableMap.<String, String>builder().
                    put(LogMessage.USER, ThreadLocalContext.getCurrentMap().get(LogMessage.USER)).
                    put(LogMessage.ACTION, "getSSOToken").
                    put(LogMessage.MESSAGE, "Failed to parse SSO response").
                    put(LogMessage.APIURL, ThreadLocalContext.getCurrentMap().get(LogMessage.APIURL)).
                    build()));
        }
        return null;
    }
}
