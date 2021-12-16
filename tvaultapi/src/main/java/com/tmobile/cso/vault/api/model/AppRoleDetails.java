// =========================================================================
// Copyright 2019 T-Mobile, US
// 
// Licensed under the Apache License, Version 2.0 (the "License");
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

package com.tmobile.cso.vault.api.model;

import javax.validation.constraints.Max;
import javax.validation.constraints.Min;
import java.io.Serializable;


public class AppRoleDetails implements Serializable {

	/**
	 * 
	 */
	private static final long serialVersionUID = 6360594229180017552L;

	private String role_name;
	private String[] policies;
	private boolean bind_secret_id;
	@Min(0)
	@Max(999999999)
	private Integer secret_id_num_uses;
	@Min(0)
	@Max(999999999)
	private Integer secret_id_ttl;
	@Min(0)
	@Max(999999999)
	private Integer token_num_uses;
	@Min(0)
	@Max(999999999)
	private Integer token_ttl;
	@Min(0)
	@Max(999999999)
	private Integer token_max_ttl;
	private String role_id;
	private String[] accessorIds;
	private AppRoleMetadata appRoleMetadata;

	public String getRole_name() {
		return role_name;
	}

	public void setRole_name(String role_name) {
		this.role_name = role_name;
	}

	public String[] getPolicies() {
		return policies;
	}

	public void setPolicies(String[] policies) {
		this.policies = policies;
	}

	public boolean isBind_secret_id() {
		return bind_secret_id;
	}

	public void setBind_secret_id(boolean bind_secret_id) {
		this.bind_secret_id = bind_secret_id;
	}

	public Integer getSecret_id_num_uses() {
		return secret_id_num_uses;
	}

	public void setSecret_id_num_uses(Integer secret_id_num_uses) {
		this.secret_id_num_uses = secret_id_num_uses;
	}

	public Integer getSecret_id_ttl() {
		return secret_id_ttl;
	}

	public void setSecret_id_ttl(Integer secret_id_ttl) {
		this.secret_id_ttl = secret_id_ttl;
	}

	public Integer getToken_num_uses() {
		return token_num_uses;
	}

	public void setToken_num_uses(Integer token_num_uses) {
		this.token_num_uses = token_num_uses;
	}

	public Integer getToken_ttl() {
		return token_ttl;
	}

	public void setToken_ttl(Integer token_ttl) {
		this.token_ttl = token_ttl;
	}

	public Integer getToken_max_ttl() {
		return token_max_ttl;
	}

	public void setToken_max_ttl(Integer token_max_ttl) {
		this.token_max_ttl = token_max_ttl;
	}

	public String getRole_id() {
		return role_id;
	}

	public void setRole_id(String role_id) {
		this.role_id = role_id;
	}

	public String[] getAccessorIds() {
		return accessorIds;
	}

	public void setAccessorIds(String[] accessorIds) {
		this.accessorIds = accessorIds;
	}

	public AppRoleMetadata getAppRoleMetadata() {
		return appRoleMetadata;
	}

	public void setAppRoleMetadata(AppRoleMetadata appRoleMetadata) {
		this.appRoleMetadata = appRoleMetadata;
	}
}
