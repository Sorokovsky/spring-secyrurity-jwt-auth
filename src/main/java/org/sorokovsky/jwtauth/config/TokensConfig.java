package org.sorokovsky.jwtauth.config;

import com.nimbusds.jose.JOSEException;
import com.nimbusds.jose.KeyLengthException;
import com.nimbusds.jose.crypto.DirectDecrypter;
import com.nimbusds.jose.crypto.DirectEncrypter;
import com.nimbusds.jose.crypto.MACSigner;
import com.nimbusds.jose.crypto.MACVerifier;
import com.nimbusds.jose.jwk.OctetSequenceKey;
import org.sorokovsky.jwtauth.deserializer.DefaultAccessTokenDeserializer;
import org.sorokovsky.jwtauth.deserializer.DefaultRefreshTokenDeserializer;
import org.sorokovsky.jwtauth.serializer.DefaultAccessTokenSerializer;
import org.sorokovsky.jwtauth.serializer.DefaultRefreshTokenSerializer;
import org.sorokovsky.jwtauth.strategy.BearerAccessTokenStorageStrategy;
import org.sorokovsky.jwtauth.strategy.CookieRefreshTokenStorageStrategy;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;

import java.text.ParseException;

@Configuration
public class TokensConfig {
    @Bean
    public DirectEncrypter encrypter(@Value("${jwt.refresh-token-key:}") String refreshTokenKey) throws ParseException, KeyLengthException {
        return new DirectEncrypter(
                OctetSequenceKey.parse(refreshTokenKey)
        );
    }

    @Bean
    DirectDecrypter decrypter(@Value("${jwt.refresh-token-key:}") String refreshTokenKey) throws ParseException, KeyLengthException {
        return new DirectDecrypter(
                OctetSequenceKey.parse(refreshTokenKey)
        );
    }

    @Bean
    public MACSigner signer(@Value("${jwt.access-token-key:}") String accessTokenKey) throws ParseException, KeyLengthException {
        return new MACSigner(
                OctetSequenceKey.parse(accessTokenKey)
        );
    }

    @Bean
    public MACVerifier verifier(@Value("${jwt.access-token-key:}") String accessTokenKey) throws ParseException, JOSEException {
        return new MACVerifier(
                OctetSequenceKey.parse(accessTokenKey)
        );
    }

    @Bean
    public BearerAccessTokenStorageStrategy bearerAccessTokenStorageStrategy(
            MACSigner signer,
            MACVerifier verifier
    ) {
        final var serializer = new DefaultAccessTokenSerializer(signer);
        final var deserializer = new DefaultAccessTokenDeserializer(verifier);
        return new BearerAccessTokenStorageStrategy(serializer, deserializer);
    }

    @Bean
    public CookieRefreshTokenStorageStrategy cookieRefreshTokenStorageStrategy(
            DirectEncrypter encrypter,
            DirectDecrypter decrypter
    ) {
        final var serializer = new DefaultRefreshTokenSerializer(encrypter);
        final var deserializer = new DefaultRefreshTokenDeserializer(decrypter);
        return new CookieRefreshTokenStorageStrategy(serializer, deserializer);
    }
}
