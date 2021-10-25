package com.tmobile.cso.vault.api.v2.controller;
import javax.servlet.http.HttpServletRequest;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.CrossOrigin;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.PutMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestHeader;
import org.springframework.web.bind.annotation.RestController;

import com.tmobile.cso.vault.api.model.Message;
import com.tmobile.cso.vault.api.service.MessageBannerService;

import io.swagger.annotations.Api;
import io.swagger.annotations.ApiOperation;

@RestController
@CrossOrigin
@Api(description = "Manage Ui message", position = 25)
public class MessageBannerController {
	@Value("${vault.auth.method}")
	private String vaultAuthMethod;

	@Autowired
	private MessageBannerService MessageBanner;

	@ApiOperation(value = "${MessageBannerController.write.value}", notes = "${MessageBannerController.write.notes}")
	@PostMapping(value = { "v2/bannermessage" }, consumes = "application/json", produces = "application/json")
	public ResponseEntity<String> write(HttpServletRequest request, @RequestHeader(value = "vault-token") String token,
			@RequestBody Message message) {

		return MessageBanner.writeBannerMessage(token, message);

	}
	
	@ApiOperation(value = "${MessageBannerController.readFromVault.value}", notes = "${MessageBannerController.readFromVault.notes}")
	@GetMapping(value = "v2/bannermessage", produces = "application/json")
	public ResponseEntity<String> readFromVault() {

		return MessageBanner.readBannerMessage();
	}
	
	@ApiOperation(value = "${MessageBannerController.updateMessage.value}", notes = "${MessageBannerController.updateMessage.notes}")
	@PutMapping(value = { "v2/bannermessage" }, consumes = "application/json", produces = "application/json")
	public ResponseEntity<String> updateMessage(HttpServletRequest request, @RequestHeader(value = "vault-token") String token,
			@RequestBody Message message){
		
		return MessageBanner.updateBannerMessage(token, message);
		
	}
}
