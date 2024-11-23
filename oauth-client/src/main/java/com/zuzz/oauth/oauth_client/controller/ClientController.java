package com.zuzz.oauth.oauth_client.controller;

import org.springframework.web.bind.annotation.RestController;

import java.util.Collections;
import java.util.Map;

import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestParam;

/**
 * REST controller for managing resource access.
 * <p>
 * Provides endpoints for users with appropriate scopes to read and write
 * resources,
 * as well as general-purpose endpoints for basic interactions.
 */
@RestController
public class ClientController {

    /**
     * Handles GET requests to the /hello endpoint.
     * <p>
     * This endpoint provides a simple "hello" message.
     * It can be used to verify that the service is operational.
     *
     * @return A {@link ResponseEntity} containing the message "hello".
     */
    @GetMapping("/hello")
    public ResponseEntity<String> hello() {
        return ResponseEntity.ok("hello");
    }

    /**
     * Handles GET requests to the /authorized endpoint.
     * <p>
     * This endpoint returns the provided authorization code in a key-value map.
     * It is typically used to test or demonstrate authorization flows.
     *
     * @param code The authorization code provided as a request parameter.
     * @return A {@link Map} containing the authorization code.
     */
    @GetMapping("/authorized")
    public Map<String, String> authorize(@RequestParam String code) {
        return Collections.singletonMap("authorizationCode", code);
    }
}
