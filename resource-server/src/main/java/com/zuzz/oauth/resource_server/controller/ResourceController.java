package com.zuzz.oauth.resource_server.controller;

import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;
import org.springframework.http.ResponseEntity;
import org.springframework.security.core.Authentication;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PostMapping;

/**
 * REST controller for managing resource access.
 * <p>
 * Provides endpoints for users with appropriate scopes to read and write
 * resources.
 * Access is restricted based on the user's authorities.
 * </p>
 */
@RestController
@RequestMapping("/resources")
public class ResourceController {

    /**
     * Handles GET requests to read user information.
     * <p>
     * This endpoint requires the {@code SCOPE_read} authority.
     * </p>
     * 
     * @param auth The {@link Authentication} object representing the currently
     *             authenticated user.
     * @return A {@link ResponseEntity} containing a message about the user's read
     *         access and their authorities.
     */
    @GetMapping("/user")
    public ResponseEntity<String> readUser(Authentication auth) {
        return ResponseEntity.ok("The user can read. " + auth.getAuthorities());
    }

    /**
     * Handles POST requests to write user information.
     * <p>
     * This endpoint requires the {@code SCOPE_write} authority.
     * </p>
     * 
     * @param auth The {@link Authentication} object representing the currently
     *             authenticated user.
     * @return A {@link ResponseEntity} containing a message about the user's write
     *         access and their authorities.
     */
    @PostMapping("/user")
    public ResponseEntity<String> writeUser(Authentication auth) {
        return ResponseEntity.ok("The user can write. " + auth.getAuthorities());
    }
}
