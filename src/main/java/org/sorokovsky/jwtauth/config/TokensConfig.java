package org.sorokovsky.jwtauth.config;

import com.nimbusds.jose.JOSEException;
import com.nimbusds.jose.KeyLengthException;
import com.nimbusds.jose.crypto.DirectDecrypter;
import com.nimbusds.jose.crypto.DirectEncrypter;
import com.nimbusds.jose.crypto.MACSigner;
import com.nimbusds.jose.crypto.MACVerifier;
import com.nimbusds.jose.jwk.OctetSequenceKey;
import org.sorokovsky.jwtauth.deserializer.AccessTokenDeserializer;
import org.sorokovsky.jwtauth.deserializer.RefreshTokenDeserializer;
import org.sorokovsky.jwtauth.serializer.AccessTokenSerializer;
import org.sorokovsky.jwtauth.serializer.RefreshTokenSerializer;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;

import java.text.ParseException;

@Configuration
public class TokensConfig {
    @Bean
    public AccessTokenDeserializer accessTokenDeserializer(
            @Value("${jwt.access-token-key:}"
            ) String accessTokenKey
    ) throws JOSEException, ParseException {
        return new AccessTokenDeserializer(new MACVerifier(
                OctetSequenceKey.parse(accessTokenKey)
        ));
    }

    @Bean
    public RefreshTokenDeserializer refreshTokenDeserializer(
            @Value("${jwt.refresh-token-key:}"
            ) String refreshTokenKey
    ) throws JOSEException, ParseException {
        return new RefreshTokenDeserializer(new DirectDecrypter(
                OctetSequenceKey.parse(refreshTokenKey)
        ));
    }

    @Bean
    public AccessTokenSerializer accessTokenSerializer(
            @Value("${jwt.access-token-key:}"
            ) String accessTokenKey
    ) throws KeyLengthException, ParseException {
        return new AccessTokenSerializer(new MACSigner(
                OctetSequenceKey.parse(accessTokenKey)
        ));
    }

    @Bean
    public RefreshTokenSerializer refreshTokenSerializer(
            @Value("${jwt.refresh-token-key:}"
            ) String refreshTokenKey) throws KeyLengthException, ParseException {
        return new RefreshTokenSerializer(
                new DirectEncrypter(
                        OctetSequenceKey.parse(refreshTokenKey)
                )
        );
    }
}
