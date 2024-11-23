package com.zuzz.oauth.oauth_server.oauth;

import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.interfaces.RSAPrivateKey;
import java.security.interfaces.RSAPublicKey;
import java.util.UUID;

import com.nimbusds.jose.jwk.JWKSet;
import com.nimbusds.jose.jwk.RSAKey;
import com.nimbusds.jose.jwk.source.ImmutableJWKSet;
import com.nimbusds.jose.jwk.source.JWKSource;
import com.nimbusds.jose.proc.SecurityContext;

import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.core.annotation.Order;
import org.springframework.http.MediaType;
import org.springframework.security.config.Customizer;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.core.userdetails.User;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.oauth2.core.AuthorizationGrantType;
import org.springframework.security.oauth2.core.ClientAuthenticationMethod;
import org.springframework.security.oauth2.core.oidc.OidcScopes;
import org.springframework.security.oauth2.jwt.JwtDecoder;
import org.springframework.security.oauth2.server.authorization.client.InMemoryRegisteredClientRepository;
import org.springframework.security.oauth2.server.authorization.client.RegisteredClient;
import org.springframework.security.oauth2.server.authorization.client.RegisteredClientRepository;
import org.springframework.security.oauth2.server.authorization.config.annotation.web.configuration.OAuth2AuthorizationServerConfiguration;
import org.springframework.security.oauth2.server.authorization.config.annotation.web.configurers.OAuth2AuthorizationServerConfigurer;
import org.springframework.security.oauth2.server.authorization.settings.AuthorizationServerSettings;
// import org.springframework.security.oauth2.server.authorization.settings.ClientSettings;
import org.springframework.security.provisioning.InMemoryUserDetailsManager;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security.web.authentication.LoginUrlAuthenticationEntryPoint;
import org.springframework.security.web.util.matcher.MediaTypeRequestMatcher;

/**
 * File to configure the OAuth2 authorization server
 * 
 */
@Configuration
@EnableWebSecurity
public class SecurityConfig {

	/**
	 * Configures the security filter chain for the authorization server.
	 * <p>
	 * This method sets up OAuth2 authorization server with default security
	 * settings,
	 * enables OpenID Connect, configures exception handling for authentication, and
	 * sets up the OAuth2 resource server to use JWT tokens.
	 * </p>
	 * 
	 * @param http The HtttpSecurity object to configure
	 * @return A configured SecurityFilterChain for the authorization server
	 * @throws Exception If an error occurs during configuration
	 */
	@Bean
	@Order(1)
	public SecurityFilterChain authorizationServerSecurityFilterChain(HttpSecurity http)
			throws Exception {
		OAuth2AuthorizationServerConfiguration.applyDefaultSecurity(http);
		http.getConfigurer(OAuth2AuthorizationServerConfigurer.class)
				.oidc(Customizer.withDefaults()); // Enable OpenID Connect
		http
				// Redirect to login page when not authenticated from the
				// authorization endpoint
				.exceptionHandling((exceptions) -> exceptions
						.defaultAuthenticationEntryPointFor(
								new LoginUrlAuthenticationEntryPoint("/login"),
								new MediaTypeRequestMatcher(MediaType.TEXT_HTML)))
				// Accept access token for User info/or Client Registration
				.oauth2ResourceServer((resourceServer) -> resourceServer
						.jwt(Customizer.withDefaults()));

		return http.build();
	}

	/**
	 * Configures the default security filter chain for the application.
	 * <p>
	 * This method sets up basic security configurations including authentication
	 * for all requests, disabling CSRF protection (for development only), and
	 * enabling form-based login.
	 * </p>
	 * 
	 * @param http The HttpSecurity object to configure
	 * @return A configured SecurityFilterChain for the default security settings.
	 * @throws Exception If an error occurs during configuration
	 */
	@Bean
	@Order(2)
	public SecurityFilterChain defaultSecurityFilterChain(HttpSecurity http)
			throws Exception {
		http
				.authorizeHttpRequests((authorize) -> authorize
						.anyRequest().authenticated())
				// for development environment only
				.csrf(csrf -> csrf.disable())
				// Form login handles the redirect to the login page from the
				// authorization server filter chain
				.formLogin(Customizer.withDefaults());

		return http.build();
	}

	/**
	 * Configures an in-memory {@link UserDetailsService} for authentication.
	 * <p>
	 * This method creates a single user with predefined credentials.
	 * </p>
	 * 
	 * @return An instance of {@link UserDetailsService} containing the in-memory
	 *         user.
	 */
	@Bean
	public UserDetailsService userDetailsService() {
		UserDetails userDetails = User.builder()
				.username("zuzz")
				.password("{noop}zuzz1221") // {noop} indicates that the password is stored in plain text
				.roles("USER")
				.build();

		return new InMemoryUserDetailsManager(userDetails);
	}

	/**
	 * Configures an in-memory {@link RegisteredClientRepository} for OAuth2/OIDC
	 * clients.
	 * <p>
	 * This method regiters a client with the following settings:
	 * <ul>
	 * <li>Client ID: {@code oauth-client}</li>
	 * <li>Client Secret: {@code 12345678910} (stored as a plain text, indicated by
	 * {@code {noop}})</li>
	 * <li>Authorization Method: {@code CLIENT_SECRET_BASIC}</li>
	 * <li>Authorization Grant Types: {@code authorization_code} and
	 * {@code refresh_token}</li>
	 * <li>Redirect URI:
	 * {@code http://127.0.0.1:8080/login/oauth2/code/oauth-client} and
	 * {@code http://127.0.0.1:8080/authorized}</li>
	 * <li>Post Logout Redirect URI: {@code http://127.0.0.1:8080/logout}</li>
	 * <li>Scopes: {@code openid}, {@code profile} and two personalized scopes
	 * ({@code write} and {@code read})</li>
	 * <li>Authorization Consent disabled</li>
	 * </ul>
	 * </p>
	 * 
	 * @return An instance of {@link RegisteredClientRepository} containing the
	 *         in-memory registered client.
	 */
	@Bean
	public RegisteredClientRepository registeredClientRepository() {
		RegisteredClient oauthClient = RegisteredClient.withId(UUID.randomUUID().toString())
				.clientId("oauth-client")
				.clientSecret("{noop}12345678910")
				.clientAuthenticationMethod(ClientAuthenticationMethod.CLIENT_SECRET_BASIC)
				/*
				 * It is used to obtain an access token on behalf of the end user using the
				 * authorization
				 * code obtained from the authorization server, useful for accessing protected
				 * resources
				 * on behalf of the user.
				 */
				.authorizationGrantType(AuthorizationGrantType.AUTHORIZATION_CODE)
				/*
				 * It is used to obtain a new access token when the current token has expired,
				 * allowing the token to be renewed without requiring the user to authenticate
				 * again,
				 * useful for obtaining and maintaining an active session and prolonging access
				 * to resources.
				 */
				.authorizationGrantType(AuthorizationGrantType.REFRESH_TOKEN)
				/*
				 * Specifies the URL to which the authorization server redirects the client
				 * along with
				 * the generated authorization code once the user has given consent.
				 */
				.redirectUri("http://127.0.0.1:8080/login/oauth2/code/oauth-client")
				.redirectUri("http://127.0.0.1:8080/authorized")
				.postLogoutRedirectUri("http://127.0.0.1:8080/logout")
				.scope(OidcScopes.OPENID)
				.scope(OidcScopes.PROFILE)
				.scope("read")
				.scope("write")
				.build();

		return new InMemoryRegisteredClientRepository(oauthClient);
	}

	/**
	 * Configures a {@link JWKSource} bean for JSON Web Key (JWK) managment.
	 * <p>
	 * This method generates an RSA key pair and creates a JWK set containing the
	 * key,
	 * which can be used for signing and verifying JWT tokens.
	 * <ul>
	 * <li>Generates an RSA public-private key pair.</li>
	 * <li>Creates an {@link RSAKey} with a unique key ID.</li>
	 * <li>Wraps the key in an {@link ImmutableJWKSet} for use in the
	 * application.</li>
	 * </ul>
	 * </p>
	 * 
	 * @return An instance of {@link JWKSource} configured with the generated RSA
	 *         key.
	 */
	@Bean
	public JWKSource<SecurityContext> jwkSource() {
		KeyPair keyPair = generateRsaKey();
		RSAPublicKey publicKey = (RSAPublicKey) keyPair.getPublic();
		RSAPrivateKey privateKey = (RSAPrivateKey) keyPair.getPrivate();
		RSAKey rsaKey = new RSAKey.Builder(publicKey)
				.privateKey(privateKey)
				.keyID(UUID.randomUUID().toString())
				.build();
		JWKSet jwkSet = new JWKSet(rsaKey);
		return new ImmutableJWKSet<>(jwkSet);
	}

	/**
	 * Generates an RSA key pair for use in signing and verifying JWT tokens.
	 * <p>
	 * This method creates a 2048-bit RSA key pair using the
	 * {@link KeyPairGenerator}.
	 * The key pair is used to secure JWTs in the application.
	 * </p>
	 * 
	 * @return A generated {@link KeyPair} with RSA keys.
	 * @throws IllegalArgumentException if an error occurs during key pair
	 *                                  generation.
	 */
	private static KeyPair generateRsaKey() {
		KeyPair keyPair;
		try {
			KeyPairGenerator keyPairGenerator = KeyPairGenerator.getInstance("RSA");
			keyPairGenerator.initialize(2048);
			keyPair = keyPairGenerator.generateKeyPair();
		} catch (Exception ex) {
			throw new IllegalStateException(ex);
		}
		return keyPair;
	}

	/**
	 * Configures a {@link JWTDecoder} bean for decoding JWT tokens.
	 * <p>
	 * This method creates a {@link JwtDecoder} using the provided
	 * {@link JWKSource}.
	 * The decoder validates and parses KWT tokens in the application.
	 * </p>
	 * 
	 * @param jwkSource The {@link JWKSource} containing the cryptographic keys.
	 * @return A configured {@link JwtDecoder} for decoding JWT tokens.
	 */
	@Bean
	public JwtDecoder jwtDecoder(JWKSource<SecurityContext> jwkSource) {
		return OAuth2AuthorizationServerConfiguration.jwtDecoder(jwkSource);
	}

	/**
	 * Configures the {@link AuthorizationServerSettings} bean.
	 * <p>
	 * This method provides default settings for the OAuth2 Authorization Server,
	 * including endpoint configuration and other server-related settings.
	 * </p>
	 * 
	 * @return A configured {@link AuthorizationServerSettings} instance with
	 *         default values.
	 */
	@Bean
	public AuthorizationServerSettings authorizationServerSettings() {
		return AuthorizationServerSettings.builder().build();
	}
}