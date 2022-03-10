package com.tmobile.cso.vault.api.model;

import java.io.Serializable;

public class AppRoleListObject implements Serializable {

    private String roleName;
    private boolean isOwner;

    public AppRoleListObject() {}

    public AppRoleListObject(String roleName, boolean isOwner) {
        this.roleName = roleName;
        this.isOwner = isOwner;
    }

    public String getRoleName() {
        return roleName;
    }

    public void setRoleName(String roleName) {
        this.roleName = roleName;
    }

    public boolean isOwner() {
        return isOwner;
    }

    public void setOwner(boolean owner) {
        isOwner = owner;
    }
}
