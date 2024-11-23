package com.zuzz.oauth.oauth_client.oauth;

import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.http.HttpMethod;
import org.springframework.security.config.Customizer;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.web.SecurityFilterChain;

/**
 * Configuration class for defining security settings in the application.
 * <p>
 * This method configures HTTP security, including authorization rules and
 * OAuth2 login settings.
 */
@Configuration
@EnableWebSecurity
public class SecurityConfig {

    /**
     * Configures the security filter chain for handling authentication and
     * authorization.
     * <p>
     * This method sets up the following security configurations:
     * <ul>
     * <li>Permits all requests to the {@code /authorized} endpoint.</li>
     * <li>Requires authentication for any other requests.</li>
     * <li>Configures OAuth2 login with a custom login page.</li>
     * </ul>
     * It also enables OAuth2 client functionality with default settings.
     *
     * @param http The {@link HttpSecurity} object to configure.
     * @return A configured {@link SecurityFilterChain} instance.
     * @throws Exception if an error occurs during configuration.
     */
    @Bean
    public SecurityFilterChain securityFilterChain(HttpSecurity http) throws Exception {
        http
                .authorizeHttpRequests((auth) -> auth
                        .requestMatchers(HttpMethod.GET, "/authorized").permitAll()
                        .anyRequest().authenticated())
                .oauth2Login((login) -> login
                        .loginPage("/oauth2/authorization/oauth-client"))
                .oauth2Client(Customizer.withDefaults());

        return http.build();
    }
}
