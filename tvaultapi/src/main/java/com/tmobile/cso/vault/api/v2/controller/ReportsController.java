// =========================================================================
// Copyright 2019 T-Mobile, US
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
package com.tmobile.cso.vault.api.v2.controller;

import javax.servlet.http.HttpServletRequest;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.CrossOrigin;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestHeader;
import org.springframework.web.bind.annotation.RestController;

import com.tmobile.cso.vault.api.model.UserDetails;
import com.tmobile.cso.vault.api.service.ReportsService;

import io.swagger.annotations.Api;
import io.swagger.annotations.ApiOperation;

@RestController
@CrossOrigin
@Api(description = "Manage Reports", position = 20)

public class ReportsController {

	@Autowired
	private ReportsService reportsService;
	
	@ApiOperation(value = "${ReportsControllerV2.safesListing.value}", notes = "${ReportsControllerV2.safesListing.notes}")
	@PostMapping(value="/v2/reports/safesByType", produces="application/json")
	public ResponseEntity<String> safesListingByType(HttpServletRequest request, @RequestHeader(value="vault-token") String token){
		UserDetails userDetails = (UserDetails) ((HttpServletRequest) request).getAttribute("UserDetails");
		return reportsService.safesListingByType(token, userDetails);
	}
	
}
