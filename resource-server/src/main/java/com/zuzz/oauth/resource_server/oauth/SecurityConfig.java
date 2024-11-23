package com.zuzz.oauth.resource_server.oauth;

import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.http.HttpMethod;
import org.springframework.security.config.Customizer;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.web.SecurityFilterChain;

@Configuration
@EnableWebSecurity
public class SecurityConfig {

    /**
     * Configures the security filter chain for the application.
     * <p>
     * This method sets up authorization rules for HTTP requests:
     * <ul>
     * <li>GET requests to {@code /resources/**} require the {@code SCOPE_read}
     * authority.</li>
     * <li>POST requests to {@code /resources/**} require the {@code SCOPE_write}
     * authority.</li>
     * <li>All other requests require authentication.</li>
     * </ul>
     * It also configures an OAuth2 resource server to validate JWT tokens.
     * </p>
     * 
     * @param http The {@link HttpSecurity} object to configure.
     * @return A configured {@link SecurityFilterChain} instance.
     * @throws Exception if an error occurs during configuration.
     */
    @Bean
    public SecurityFilterChain filterChain(HttpSecurity http) throws Exception {
        http
                .authorizeHttpRequests(authorize -> authorize
                        .requestMatchers(HttpMethod.GET, "/resources/**").hasAnyAuthority("SCOPE_read", "SCOPE_write")
                        .requestMatchers(HttpMethod.POST, "/resources/**").hasAuthority("SCOPE_write")
                        .anyRequest().authenticated())
                .oauth2ResourceServer((oauth2) -> oauth2
                        .jwt(Customizer.withDefaults()));

        return http.build();
    }
}
