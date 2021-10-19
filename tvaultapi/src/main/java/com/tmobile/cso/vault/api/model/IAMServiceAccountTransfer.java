package com.tmobile.cso.vault.api.model;

import com.fasterxml.jackson.annotation.JsonProperty;
import org.hibernate.validator.constraints.Email;
import org.hibernate.validator.constraints.NotBlank;
import javax.validation.constraints.Pattern;
import javax.validation.constraints.Size;

public class IAMServiceAccountTransfer {

    @JsonProperty("ad_group")
    private String adSelfSupportGroup;

    @JsonProperty("application_id")
    private String applicationId;

    @JsonProperty("application_name")
    private String applicationName;

    @JsonProperty("application_tag")
    private String applicationTag;

    @NotBlank
    @Pattern( regexp = "^$|^[0-9]+$", message="Invalid AWS account id")
    @Size(min = 1, max = 12, message = "AWSAccountId specified should be maximum 12 characters only")
    private String awsAccountId;

    @Pattern(regexp = "^$|^[a-zA-Z0-9_-]+$", message = "Owner can have alphabets, numbers, _ and - characters only")
    @JsonProperty("owner_ntid")
    private String ownerNtid;

    @Email
    @JsonProperty("owner_email")
    private String ownerEmail;

    @NotBlank
    @Size(min = 1, max = 64, message = "UserName specified should be minimum 1 character and maximum 64 characters only")
    @Pattern(regexp = "^[a-zA-Z0-9+=,.@_-]+$", message = "Name can have alphabets, numbers, plus (+), equal (=), comma (,), period (.), at (@), underscore (_), and hyphen (-)  only")
    private String userName;

    public IAMServiceAccountTransfer() {}
    public IAMServiceAccountTransfer(String userName, String awsAccountId, String ownerNtid, String ownerEmail, String applicationId,
                                     String applicationName, String applicationTag, String adSelfSupportGroup) {
        this.adSelfSupportGroup = adSelfSupportGroup;
        this.applicationId = applicationId;
        this.applicationName = applicationName;
        this.applicationTag = applicationTag;
        this.awsAccountId = awsAccountId;
        this.ownerNtid = ownerNtid;
        this.ownerEmail = ownerEmail;
        this.userName = userName;
    }

    public String getAdSelfSupportGroup() {
        return adSelfSupportGroup;
    }

    public void setAdSelfSupportGroup(String adSelfSupportGroup) {
        this.adSelfSupportGroup = adSelfSupportGroup;
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

    public String getAwsAccountId() {
        return awsAccountId;
    }

    public void setAwsAccountId(String awsAccountId) {
        this.awsAccountId = awsAccountId;
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

    public String getUserName() {
        return userName;
    }

    public void setUserName(String userName) {
        this.userName = userName;
    }
}
