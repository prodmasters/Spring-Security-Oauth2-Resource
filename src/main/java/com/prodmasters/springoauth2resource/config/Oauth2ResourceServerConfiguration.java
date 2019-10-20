package com.prodmasters.springoauth2resource.config;

import com.prodmasters.springoauth2resource.exception.CustomTokenStoreException;
import com.sun.org.apache.xml.internal.security.exceptions.Base64DecodingException;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.oauth2.config.annotation.web.configuration.EnableResourceServer;
import org.springframework.security.oauth2.config.annotation.web.configuration.ResourceServerConfigurerAdapter;
import org.springframework.security.oauth2.config.annotation.web.configurers.ResourceServerSecurityConfigurer;
import org.springframework.security.oauth2.provider.authentication.OAuth2AuthenticationManager;
import org.springframework.security.oauth2.provider.token.DefaultTokenServices;
import org.springframework.security.oauth2.provider.token.ResourceServerTokenServices;
import org.springframework.security.oauth2.provider.token.TokenStore;
import org.springframework.security.oauth2.provider.token.store.DelegatingJwtClaimsSetVerifier;
import org.springframework.security.oauth2.provider.token.store.IssuerClaimVerifier;
import org.springframework.security.oauth2.provider.token.store.JwtClaimsSetVerifier;

import java.io.IOException;
import java.net.MalformedURLException;
import java.net.URL;
import java.security.NoSuchAlgorithmException;
import java.security.spec.InvalidKeySpecException;
import java.util.Arrays;

@EnableResourceServer
@Configuration
public class Oauth2ResourceServerConfiguration extends ResourceServerConfigurerAdapter {

    @Value("${spring.oauth2.jwt.issuer}")
    private String issuer;
    @Value("${spring.oauth2.jwt.issuer.cert}")
    private String issuerCertFile;
    @Value("${spring.oauth2.jwt.resourceId}")
    private String resourceId;
    @Override
    public void configure(ResourceServerSecurityConfigurer resources) throws Exception {
        resources.resourceId(resourceId)
                .authenticationManager(authenticationManagerBean())
                .tokenServices(tokenService());
    }

    @Bean
    public ResourceServerTokenServices tokenService() throws IOException, CustomTokenStoreException {
        DefaultTokenServices tokenServices = new DefaultTokenServices();
        tokenServices.setTokenStore(tokenStore());
        return tokenServices;
    }

    @Bean
    public AuthenticationManager authenticationManagerBean() throws Exception {
        OAuth2AuthenticationManager authenticationManager = new OAuth2AuthenticationManager();
        authenticationManager.setTokenServices(tokenService());
        return authenticationManager;
    }

    @Bean
    public JwtClaimsSetVerifier jwtClaimsSetVerifier() throws MalformedURLException {
        return new DelegatingJwtClaimsSetVerifier(Arrays.asList(new IssuerClaimVerifier(new URL(issuer))));
    }

    @Bean
    public TokenStore tokenStore() throws IOException, CustomTokenStoreException {
        return new CustomTokenStore(jwtClaimsSetVerifier(),issuerCertFile);
    }

    @Override
    public void configure(HttpSecurity http) throws Exception {
        http.httpBasic().disable().anonymous().and().authorizeRequests().antMatchers("/user/**").authenticated()
                .antMatchers("/public/**").permitAll();
    }

}
