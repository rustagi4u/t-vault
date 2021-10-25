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

import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

import org.apache.commons.collections.MapUtils;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.stereotype.Component;

import com.google.common.collect.ImmutableMap;
import com.tmobile.cso.vault.api.common.TVaultConstants;
import com.tmobile.cso.vault.api.controller.ControllerUtil;
import com.tmobile.cso.vault.api.exception.LogMessage;
import com.tmobile.cso.vault.api.model.Safe;
import com.tmobile.cso.vault.api.model.Safes;
import com.tmobile.cso.vault.api.model.UserDetails;
import com.tmobile.cso.vault.api.utils.JSONUtil;
import com.tmobile.cso.vault.api.utils.SafeUtils;
import com.tmobile.cso.vault.api.utils.ThreadLocalContext;

@Component
public class ReportsService {

	@Value("${vault.port}")
	private String vaultPort;

	@Autowired
	private SafeUtils safeUtils;

	@Value("${vault.auth.method}")
	private String vaultAuthMethod;

	private static Logger log = LogManager.getLogger(ReportsService.class);

	/**
	 * Generates the list of Safes by Types
	 * @param token
	 * @return
	 */
	public ResponseEntity<String> safesListingByType(String token,  UserDetails userDetails) {
		log.debug(JSONUtil.getJSON(ImmutableMap.<String, String>builder().
			      put(LogMessage.USER, ThreadLocalContext.getCurrentMap().get(LogMessage.USER).toString()).
				  put(LogMessage.ACTION, "safesListingByType").
			      put(LogMessage.MESSAGE, "Trying to get list of SafesByType").
			      put(LogMessage.APIURL, ThreadLocalContext.getCurrentMap().get(LogMessage.APIURL).toString()).
			      build()));
		HashMap<String, List<String>> allSafeNames = ControllerUtil.getAllExistingSafeNames(userDetails.getSelfSupportToken());
		if (MapUtils.isEmpty(allSafeNames)) {
			return ResponseEntity.status(HttpStatus.OK).body("No safes are available");
		}
		else {
			Safes safes = new Safes();
			 List<Safe> appSafes = new ArrayList<Safe>();	
			 List<Safe> sharedSafes =  new ArrayList<Safe>();	
			 List<Safe> usersSafes = new ArrayList<Safe>();	
			 safes.setAppSafes(appSafes);
			 safes.setSharedSafes(sharedSafes);
			 safes.setUsersSafes(usersSafes);
			
			for (Map.Entry<String,List<String>> set : allSafeNames.entrySet()) {
				String safeType = set.getKey();
				List<String> safeNames = set.getValue();
				for (String safeName: safeNames) {
					Safe safeDetails = safeUtils.getSafeMetaData(userDetails.getSelfSupportToken(), safeType, safeName);
					safeDetails.setPath(safeType+"/"+safeName);
					if (TVaultConstants.APPS.equals(safeType)) {
						appSafes.add(safeDetails);
					}
					else if (TVaultConstants.SHARED.equals(safeType)) {
						sharedSafes.add(safeDetails);
					}
					else {
						usersSafes.add(safeDetails);
					}
				}
	        }
			return ResponseEntity.status(HttpStatus.OK).body(JSONUtil.getJSON(safes));
		}
		
	}

}
