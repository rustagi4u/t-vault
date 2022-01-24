package com.tmobile.cso.vault.api.v2.controller;

import static org.hamcrest.Matchers.containsString;
import static org.mockito.Matchers.eq;
import static org.mockito.Mockito.when;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.content;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

import org.junit.Before;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.mockito.InjectMocks;
import org.mockito.Mock;
import org.mockito.Mockito;
import org.mockito.MockitoAnnotations;
import org.springframework.context.annotation.ComponentScan;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.test.context.ContextConfiguration;
import org.springframework.test.context.junit4.SpringJUnit4ClassRunner;
import org.springframework.test.context.web.WebAppConfiguration;
import org.springframework.test.web.servlet.MockMvc;
import org.springframework.test.web.servlet.request.MockMvcRequestBuilders;
import org.springframework.test.web.servlet.setup.MockMvcBuilders;

import com.tmobile.cso.vault.api.main.Application;
import com.tmobile.cso.vault.api.model.Message;
import com.tmobile.cso.vault.api.service.MessageBannerService;

@RunWith(SpringJUnit4ClassRunner.class)
@ContextConfiguration(classes = Application.class)
@ComponentScan(basePackages={"com.tmobile.cso.vault.api"})
@WebAppConfiguration
public class MessageBannerControllerTest {
	
	private MockMvc mockMvc;
	
	@Mock
    private MessageBannerService messageBannerService;
	
	@InjectMocks
    private MessageBannerController MessageBannerController;
	
	@Before
    public void setUp() {
        MockitoAnnotations.initMocks(this);
        this.mockMvc = MockMvcBuilders.standaloneSetup(MessageBannerController).build();
	}
	
	@Test
	public void test_writeBannerMessage() throws Exception {

        String inputJson ="{\r\n"
        		+ "  \"data\": {\r\n"
        		+ "    \"message1\": \"value1\",\r\n"
        		+ "    \"message2\": \"value2\"\r\n"
        		+ "  }\r\n"
        		+ "}";
        String responseMessage = "{\"messages\":[\"message saved to vault\"]}";
        ResponseEntity<String> responseEntityExpected = ResponseEntity.status(HttpStatus.OK).body(responseMessage);
        when(messageBannerService.writeBannerMessage(eq("5PDrOhsy4ig8L3EpsJZSLAMg"), Mockito.any())).thenReturn(responseEntityExpected);
        mockMvc.perform(MockMvcRequestBuilders.post("/v2/bannermessage")
                .header("vault-token", "5PDrOhsy4ig8L3EpsJZSLAMg")
                .header("Content-Type", "application/json;charset=UTF-8")
                .content(inputJson))
                .andExpect(status().isOk())
                .andExpect(content().string(containsString(responseMessage)));
    }
	
	@Test
    public void test_readBannerMessage() throws Exception {

        String responseMessage = "{  \"data\": {    \"message1\": \"value1\",    \"message2\": \"value2\"  }}";
        ResponseEntity<String> responseEntityExpected = ResponseEntity.status(HttpStatus.OK).body(responseMessage);
        when(messageBannerService.readBannerMessage()).thenReturn(responseEntityExpected);
        mockMvc.perform(MockMvcRequestBuilders.get("/v2/bannermessage?path=metadata/users/message")
                .header("Content-Type", "application/json;charset=UTF-8"))
                .andExpect(status().isOk())
                .andExpect(content().string(containsString(responseMessage)));

    }
	
	@Test
	public void test_updateBannerMessage() throws Exception {
		
		String inputJson ="{\r\n"
        		+ "  \"data\": {\r\n"
        		+ "    \"message1\": \"value1\",\r\n"
        		+ "    \"message2\": \"value2\"\r\n"
        		+ "  }\r\n"
        		+ "}";
                       
        String responseMessage = "{\"messages\":[\"updated message saved to vault\"]}";
        ResponseEntity<String> responseEntityExpected = ResponseEntity.status(HttpStatus.OK).body(responseMessage);
        when(messageBannerService.updateBannerMessage(eq("5PDrOhsy4ig8L3EpsJZSLAMg"), Mockito.any())).thenReturn(responseEntityExpected);
        mockMvc.perform(MockMvcRequestBuilders.put("/v2/bannermessage")
                .header("vault-token", "5PDrOhsy4ig8L3EpsJZSLAMg")
                .header("Content-Type", "application/json;charset=UTF-8")
                .content(inputJson))
                .andExpect(status().isOk())
                .andExpect(content().string(containsString(responseMessage)));
		
	} 

}
