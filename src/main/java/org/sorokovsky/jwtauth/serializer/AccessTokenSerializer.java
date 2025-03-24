package org.sorokovsky.jwtauth.serializer;

import com.nimbusds.jose.JOSEException;
import com.nimbusds.jose.JWSAlgorithm;
import com.nimbusds.jose.JWSHeader;
import com.nimbusds.jose.JWSSigner;
import com.nimbusds.jwt.JWTClaimsSet;
import com.nimbusds.jwt.SignedJWT;
import lombok.Setter;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.sorokovsky.jwtauth.model.TokenModel;

import java.util.Date;
import java.util.function.Function;

public class AccessTokenSerializer implements Function<TokenModel, String> {
    private static final Logger LOGGER = LoggerFactory.getLogger(AccessTokenSerializer.class);
    private final JWSSigner signer;
    @Setter
    private JWSAlgorithm algorithm = JWSAlgorithm.HS256;

    public AccessTokenSerializer(JWSSigner signer) {
        this.signer = signer;
    }

    @Override
    public String apply(TokenModel tokenModel) {
        var header = new JWSHeader.Builder(algorithm)
                .keyID(tokenModel.id().toString())
                .build();
        var claims = new JWTClaimsSet.Builder()
                .jwtID(tokenModel.id().toString())
                .subject(tokenModel.email())
                .issueTime(Date.from(tokenModel.createdAt()))
                .expirationTime(Date.from(tokenModel.expiresAt()))
                .build();
        try {
            var signed = new SignedJWT(header, claims);
            signed.sign(signer);
            return signed.serialize();
        } catch (JOSEException e) {
            LOGGER.error(e.getMessage(), e);
        }
        return null;
    }
}
