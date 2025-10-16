package com.hon.aecs.prm.syncProgramMembers.security;

import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.interfaces.RSAPublicKey;
import java.util.List;
import java.util.UUID;

import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.config.Customizer;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.http.SessionCreationPolicy;
import org.springframework.security.core.userdetails.User;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.oauth2.jwt.JwtDecoder;
import org.springframework.security.oauth2.jwt.JwtEncoder;
import org.springframework.security.oauth2.jwt.NimbusJwtDecoder;
import org.springframework.security.oauth2.jwt.NimbusJwtEncoder;
import org.springframework.security.provisioning.InMemoryUserDetailsManager;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.stereotype.Component;

import com.nimbusds.jose.JOSEException;
import com.nimbusds.jose.KeySourceException;
import com.nimbusds.jose.jwk.JWK;
import com.nimbusds.jose.jwk.JWKSelector;
import com.nimbusds.jose.jwk.JWKSet;
import com.nimbusds.jose.jwk.RSAKey;
import com.nimbusds.jose.jwk.source.JWKSource;
import com.nimbusds.jose.proc.SecurityContext;

@Configuration
@Component
public class HONPRMMembersSecurityService {
	//Create a security chain
	@SuppressWarnings("removal")
	@Bean
	public SecurityFilterChain filterChain(HttpSecurity http) throws Exception {
		http
		.authorizeHttpRequests(auth -> auth.anyRequest().authenticated())
		.httpBasic(Customizer.withDefaults())
		.sessionManagement(session -> session.sessionCreationPolicy(SessionCreationPolicy.STATELESS))
		.csrf(csrf -> csrf.disable())
		.headers(headers -> headers
                .frameOptions(frameOptions -> frameOptions
                        .sameOrigin()
                    )
                )
		.oauth2ResourceServer(oauth2ResourceServer -> oauth2ResourceServer.jwt(jwt -> {
			try {
				jwt.decoder(jwtDecoder(this.rsaKey(this.keyPair())));
			} catch (JOSEException e) {
				// TODO Auto-generated catch block
				e.printStackTrace();
			}
		}));
		return http.build();

	
	//Create In Memory user
	@Bean
	public UserDetailsService userDetailsService() {
		var securityUser = User.withUsername("infodba")
		.password("infodba").passwordEncoder(password -> bCryptPasswordEncoder().encode(password))
		.roles("USER")
		.build();
		
		return new InMemoryUserDetailsManager(securityUser);
	}
	
	@Bean
	public BCryptPasswordEncoder bCryptPasswordEncoder() {
		return new BCryptPasswordEncoder();
	}
	
	//Create Key Pair using Key Pair Generator
	@Bean
	public KeyPair keyPair(){
		try {
			var keyPairGenerator = KeyPairGenerator.getInstance("RSA");
			keyPairGenerator.initialize(5096);
			return keyPairGenerator.generateKeyPair();
		}catch (Exception ex) {
			throw new RuntimeException(ex);
		}
	}
	
	//Create RSA Key using generated Key Pair
	@Bean
	public RSAKey rsaKey(KeyPair keyPair) {
		return new RSAKey.Builder((RSAPublicKey) keyPair.getPublic())
		.privateKey(keyPair.getPrivate())
		.keyID(UUID.randomUUID().toString())
		.build();
	}
	
	//Create JWK Source using generated RSA key
	@Bean
	public JWKSource<SecurityContext> jwkSource(RSAKey rsaKey) {
		//1. Create JWKSet
		var jwkSet = new JWKSet(rsaKey);
		
		//2. Create JWKSource and and created jwkSet to it
		@SuppressWarnings("rawtypes")
		var jwkSource = new JWKSource() {
 
			@Override
			public List<JWK> get(JWKSelector jwkSelector, SecurityContext context) throws KeySourceException {
				return jwkSelector.select(jwkSet);
			}
		};
		return jwkSource;
	}
	
	//Create JWT Decoder using RSA public key
	//@Bean
	public JwtDecoder jwtDecoder(RSAKey rsaKey) throws JOSEException {
		return NimbusJwtDecoder.withPublicKey(rsaKey.toRSAPublicKey()).build();
	}
	
	//Create JWT Encoder using generated JWK Source
	@Bean
	public JwtEncoder jwtEncoder(JWKSource<SecurityContext> jwkSource) {
		return new NimbusJwtEncoder(jwkSource);
	}
}
