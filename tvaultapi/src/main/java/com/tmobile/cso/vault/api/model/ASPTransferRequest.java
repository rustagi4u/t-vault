package com.tmobile.cso.vault.api.model;

import com.fasterxml.jackson.annotation.JsonProperty;
import org.hibernate.validator.constraints.Email;
import org.hibernate.validator.constraints.NotBlank;

import javax.validation.constraints.Pattern;
import javax.validation.constraints.Size;

public class ASPTransferRequest {

    @JsonProperty("application_id")
    private String applicationId;

    @JsonProperty("application_name")
    private String applicationName;

    @JsonProperty("application_tag")
    private String applicationTag;

    @NotBlank
    @Pattern(regexp = "^$|^[a-zA-Z0-9_-]+$", message = "Owner can have alphabets, numbers, _ and - characters only")
    @JsonProperty("owner_ntid")
    private String ownerNtid;

    @NotBlank
    @Email
    @Size(min = 1, message = "Owner Email can not be null or empty")
    @Pattern(regexp = "^[_A-Za-z0-9-]+(\\.[_A-Za-z0-9-]+)*@[A-Za-z0-9-]+(\\.[A-Za-z0-9-]+)*(\\.[A-Za-z]{2,})$", message = "Owner Email is not valid")
    @JsonProperty("owner_email")
    private String ownerEmail;

    @NotBlank
    @Size(min = 11, message = "Azure service principal name specified should be minimum 11 characters only")
    @Pattern(regexp = "^[a-zA-Z0-9_-]+$", message = "Azure service principal name can have alphabets, numbers, _ and - characters only")
    private String servicePrincipalName;

    public ASPTransferRequest() {}
    public ASPTransferRequest(String servicePrincipalName, String ownerNtid, String ownerEmail, String applicationId,
                              String applicationName, String applicationTag) {
        this.applicationId = applicationId;
        this.applicationName = applicationName;
        this.applicationTag = applicationTag;
        this.ownerNtid = ownerNtid;
        this.ownerEmail = ownerEmail;
        this.servicePrincipalName = servicePrincipalName;
    }

    public String getApplicationId() {
        return applicationId;
    }

    public void setApplicationId(String applicationId) {
        this.applicationId = applicationId;
    }

    public String getApplicationName() {
        return applicationName;
    }

    public void setApplicationName(String applicationName) {
        this.applicationName = applicationName;
    }

    public String getApplicationTag() {
        return applicationTag;
    }

    public void setApplicationTag(String applicationTag) {
        this.applicationTag = applicationTag;
    }

    public String getOwnerNtid() {
        return ownerNtid;
    }

    public void setOwnerNtid(String ownerNtid) {
        this.ownerNtid = ownerNtid;
    }

    public String getOwnerEmail() {
        return ownerEmail;
    }

    public void setOwnerEmail(String ownerEmail) {
        this.ownerEmail = ownerEmail;
    }

    public String getServicePrincipalName() {
        return servicePrincipalName;
    }

    public void setServicePrincipalName(String servicePrincipalName) {
        this.servicePrincipalName = servicePrincipalName;
    }
}
