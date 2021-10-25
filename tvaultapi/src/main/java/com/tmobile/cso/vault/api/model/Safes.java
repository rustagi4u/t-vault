
package com.tmobile.cso.vault.api.model;

import java.io.Serializable;
import java.util.ArrayList;
import java.util.List;

public class Safes implements Serializable{

	
	/**
	 * 
	 */
	private static final long serialVersionUID = -5874612329209724629L;
	private List<Safe> appSafes = new ArrayList<Safe>();	
	private List<Safe> sharedSafes =  new ArrayList<Safe>();	
	private List<Safe> usersSafes = new ArrayList<Safe>();	
	public Safes() {
		super();
	}
	public List<Safe> getAppSafes() {
		return appSafes;
	}
	public void setAppSafes(List<Safe> appSafes) {
		this.appSafes = appSafes;
	}
	public List<Safe> getSharedSafes() {
		return sharedSafes;
	}
	public void setSharedSafes(List<Safe> sharedSafes) {
		this.sharedSafes = sharedSafes;
	}
	public List<Safe> getUsersSafes() {
		return usersSafes;
	}
	public void setUsersSafes(List<Safe> usersSafes) {
		this.usersSafes = usersSafes;
	}
	@Override
	public String toString() {
		return "Safes [appSafes=" + appSafes + ", sharedSafes=" + sharedSafes + ", usersSafes=" + usersSafes + "]";
	}

	
	
}
