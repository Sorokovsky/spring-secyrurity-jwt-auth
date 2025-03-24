package org.sorokovsky.jwtauth.deserializer;

import com.nimbusds.jose.JOSEException;
import com.nimbusds.jose.JWSSigner;
import com.nimbusds.jose.JWSVerifier;
import com.nimbusds.jwt.SignedJWT;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.sorokovsky.jwtauth.model.TokenModel;

import java.text.ParseException;
import java.util.UUID;
import java.util.function.Function;

public class AccessTokenDeserializer implements Function<String, TokenModel> {
    private static final Logger LOGGER = LoggerFactory.getLogger(AccessTokenDeserializer.class);

    private final JWSVerifier verifier;

    public AccessTokenDeserializer(JWSVerifier verifier) {
        this.verifier = verifier;
    }

    @Override
    public TokenModel apply(String s) {
        try {
            var signed = SignedJWT.parse(s);
            if(signed.verify(verifier)) {
                var claims = signed.getJWTClaimsSet();
                return new TokenModel(UUID.fromString(claims.getJWTID()), claims.getSubject(),
                        claims.getIssueTime().toInstant(), claims.getExpirationTime().toInstant()
                );
            } else {
                return null;
            }
        } catch (ParseException | JOSEException e) {
            LOGGER.error(e.getMessage(), e);
        }
        return null;
    }
}
