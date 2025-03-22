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

public class RefreshTokenSerializer implements Function<TokenModel, String> {
    private static final Logger LOGGER = LoggerFactory.getLogger(RefreshTokenSerializer.class);

    private final JWSSigner signer;
    @Setter
    private JWSAlgorithm algorithm = JWSAlgorithm.HS256;

    public RefreshTokenSerializer(JWSSigner signer) {
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
                .expirationTime(Date.from(tokenModel.expiresAt()))
                .issueTime(Date.from(tokenModel.createdAt()))
                .build();
        var signedJWT = new SignedJWT(header, claims);
        try {
            signedJWT.sign(signer);
            return signedJWT.serialize();
        } catch (JOSEException exception) {
            LOGGER.error(exception.getMessage(), exception);
        }
        return null;
    }
}
