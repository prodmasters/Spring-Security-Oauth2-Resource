package com.prodmasters.springoauth2resource.config;

import com.prodmasters.springoauth2resource.exception.CustomTokenStoreException;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.core.io.ClassPathResource;
import org.springframework.core.io.Resource;
import org.springframework.security.jwt.crypto.sign.RsaVerifier;
import org.springframework.security.oauth2.common.OAuth2AccessToken;
import org.springframework.security.oauth2.common.OAuth2RefreshToken;
import org.springframework.security.oauth2.provider.OAuth2Authentication;
import org.springframework.security.oauth2.provider.token.TokenStore;
import org.springframework.security.oauth2.provider.token.store.JwtAccessTokenConverter;
import org.springframework.security.oauth2.provider.token.store.JwtClaimsSetVerifier;
import org.springframework.security.oauth2.provider.token.store.JwtTokenStore;

import java.io.BufferedReader;
import java.io.IOException;
import java.io.InputStreamReader;
import java.nio.charset.StandardCharsets;
import java.security.KeyFactory;
import java.security.NoSuchAlgorithmException;
import java.security.PublicKey;
import java.security.interfaces.RSAPublicKey;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.X509EncodedKeySpec;
import java.util.Base64;
import java.util.Collection;
import java.util.stream.Collectors;

public class CustomTokenStore implements TokenStore {

    private final JwtTokenStore jwtTokenStore;
    private Logger log= LoggerFactory.getLogger(CustomTokenStore.class);

    public CustomTokenStore(JwtClaimsSetVerifier jwtClaimsSetVerifier,String pemFile) throws CustomTokenStoreException {
        try {
            JwtAccessTokenConverter accessTokenConverter = new JwtAccessTokenConverter();
            Resource resource = new ClassPathResource(pemFile);
            String key =
                    new BufferedReader(new InputStreamReader(resource.getInputStream(),
                            StandardCharsets.UTF_8)).lines().collect(Collectors.joining());
            RSAPublicKey publicKey=(RSAPublicKey) generatePublicKey(key);
            accessTokenConverter.setVerifier(new RsaVerifier(publicKey));
            accessTokenConverter.setVerifierKey("-----BEGIN PUBLIC KEY-----\n" + new String(Base64.getEncoder().encode(publicKey.getEncoded())) + "\n-----END PUBLIC KEY-----");
            accessTokenConverter.setJwtClaimsSetVerifier(jwtClaimsSetVerifier);
            this.jwtTokenStore = new JwtTokenStore(accessTokenConverter);
        }
        catch(IOException e){
            log.error("IOException when loading pem file "+pemFile,e);
            throw new CustomTokenStoreException(e);
        } catch (NoSuchAlgorithmException e) {
            log.error("NoSuchAlgorithm exception when creating RSA public key",e);
            throw new CustomTokenStoreException(e);
        } catch (InvalidKeySpecException e) {
            log.error("InvalidKeySpecException when creating RSA public key ",e);
            throw new CustomTokenStoreException(e);
        }
    }
    @Override
    public OAuth2Authentication readAuthentication(OAuth2AccessToken oAuth2AccessToken) {
        return this.jwtTokenStore.readAuthentication(oAuth2AccessToken);
    }

    @Override
    public OAuth2Authentication readAuthentication(String s) {
        return this.jwtTokenStore.readAuthentication(s);
    }

    @Override
    public void storeAccessToken(OAuth2AccessToken oAuth2AccessToken, OAuth2Authentication oAuth2Authentication) {
        this.jwtTokenStore.storeAccessToken(oAuth2AccessToken,oAuth2Authentication);
    }

    @Override
    public OAuth2AccessToken readAccessToken(String s) {
        return this.jwtTokenStore.readAccessToken(s);
    }

    @Override
    public void removeAccessToken(OAuth2AccessToken oAuth2AccessToken) {
       this.jwtTokenStore.removeAccessToken(oAuth2AccessToken);
    }

    @Override
    public void storeRefreshToken(OAuth2RefreshToken oAuth2RefreshToken, OAuth2Authentication oAuth2Authentication) {
       throw new UnsupportedOperationException("Operation not supported");
    }

    @Override
    public OAuth2RefreshToken readRefreshToken(String s) {
        throw new UnsupportedOperationException("Operation not supported");
    }

    @Override
    public OAuth2Authentication readAuthenticationForRefreshToken(OAuth2RefreshToken oAuth2RefreshToken) {
        throw new UnsupportedOperationException("Operation not supported");
    }

    @Override
    public void removeRefreshToken(OAuth2RefreshToken oAuth2RefreshToken) {
        throw new UnsupportedOperationException("Operation not supported");

    }

    @Override
    public void removeAccessTokenUsingRefreshToken(OAuth2RefreshToken oAuth2RefreshToken) {
        throw new UnsupportedOperationException("Operation not supported");
    }

    @Override
    public OAuth2AccessToken getAccessToken(OAuth2Authentication oAuth2Authentication) {
        return this.jwtTokenStore.getAccessToken(oAuth2Authentication);
    }

    @Override
    public Collection<OAuth2AccessToken> findTokensByClientIdAndUserName(String s, String s1) {
        throw new UnsupportedOperationException("Operation not supported");
    }

    @Override
    public Collection<OAuth2AccessToken> findTokensByClientId(String s) {
        throw new UnsupportedOperationException("Operation not supported");
    }

    private PublicKey generatePublicKey(String key) throws NoSuchAlgorithmException, InvalidKeySpecException {
        String publicKeyPEM = key.replace("-----BEGIN PUBLIC KEY-----", "");
        publicKeyPEM = publicKeyPEM.replace("-----END PUBLIC KEY-----", "");

        byte [] decoded = Base64.getDecoder().decode(publicKeyPEM.getBytes(StandardCharsets.UTF_8));

        X509EncodedKeySpec spec =
                new X509EncodedKeySpec(decoded);
        KeyFactory kf = KeyFactory.getInstance("RSA");
        return kf.generatePublic(spec);
    }
}
