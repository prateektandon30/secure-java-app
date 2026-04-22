package com.secureapp;

import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.autoconfigure.web.servlet.AutoConfigureMockMvc;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.http.MediaType;
import org.springframework.test.web.servlet.MockMvc;

import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.post;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.*;

/**
 * Integration tests — suffixed *IT so maven-failsafe picks them up.
 * During the IAST stage in Jenkins, the app runs with the IAST agent
 * (-javaagent:/opt/iast/agent.jar). As these tests exercise the app,
 * the agent instruments every code path and reports findings.
 */
@SpringBootTest(webEnvironment = SpringBootTest.WebEnvironment.RANDOM_PORT)
@AutoConfigureMockMvc
class AuthFlowIT {

    @Autowired MockMvc mvc;

    @Test
    void register_and_login_flow() throws Exception {
        // 1. Register
        mvc.perform(post("/api/auth/register")
                .contentType(MediaType.APPLICATION_JSON)
                .content("""
                    {"username":"testuser","email":"test@example.com","password":"Password1!"}
                """))
            .andExpect(status().isOk())
            .andExpect(jsonPath("$.message").value("User registered successfully"));

        // 2. Login → get token
        var result = mvc.perform(post("/api/auth/login")
                .contentType(MediaType.APPLICATION_JSON)
                .content("""
                    {"username":"testuser","password":"Password1!"}
                """))
            .andExpect(status().isOk())
            .andExpect(jsonPath("$.token").exists())
            .andReturn();

        String body = result.getResponse().getContentAsString();
        String token = body.replaceAll(".*\"token\":\"([^\"]+)\".*", "$1");

        // 3. Access protected endpoint with token
        mvc.perform(get("/api/users/me")
                .header("Authorization", "Bearer " + token))
            .andExpect(status().isOk())
            .andExpect(jsonPath("$.username").value("testuser"));
    }

    @Test
    void protected_endpoint_without_token_returns_401() throws Exception {
        mvc.perform(get("/api/users/me"))
            .andExpect(status().isUnauthorized());
    }

    @Test
    void invalid_login_returns_401() throws Exception {
        mvc.perform(post("/api/auth/login")
                .contentType(MediaType.APPLICATION_JSON)
                .content("""
                    {"username":"nobody","password":"wrongpassword"}
                """))
            .andExpect(status().isUnauthorized());
    }
}
