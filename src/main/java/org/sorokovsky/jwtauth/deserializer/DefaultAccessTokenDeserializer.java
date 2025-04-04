package org.sorokovsky.jwtauth.deserializer;

import com.nimbusds.jose.JOSEException;
import com.nimbusds.jose.JWSVerifier;
import com.nimbusds.jwt.SignedJWT;
import lombok.RequiredArgsConstructor;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.sorokovsky.jwtauth.contract.Token;

import java.text.ParseException;

@RequiredArgsConstructor
public class DefaultAccessTokenDeserializer extends AbstractTokenDeserializer {
    private static final Logger LOGGER = LoggerFactory.getLogger(DefaultAccessTokenDeserializer.class);
    private final JWSVerifier verifier;

    @Override
    public Token apply(String string) {
        if (string == null) return null;
        try {
            final var signed = SignedJWT.parse(string);
            signed.verify(verifier);
            return extractFromClaims(signed.getJWTClaimsSet());
        } catch (ParseException | JOSEException e) {
            LOGGER.error(e.getMessage(), e);
            return null;
        }
    }
}
