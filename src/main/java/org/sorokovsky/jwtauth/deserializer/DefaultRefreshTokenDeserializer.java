package org.sorokovsky.jwtauth.deserializer;

import com.nimbusds.jose.JOSEException;
import com.nimbusds.jose.JWEDecrypter;
import com.nimbusds.jwt.EncryptedJWT;
import lombok.RequiredArgsConstructor;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.sorokovsky.jwtauth.contract.Token;

import java.text.ParseException;

@RequiredArgsConstructor
public class DefaultRefreshTokenDeserializer extends AbstractTokenDeserializer {
    private final static Logger LOGGER = LoggerFactory.getLogger(DefaultRefreshTokenDeserializer.class);
    private final JWEDecrypter decrypter;

    @Override
    public Token apply(String string) {
        try {
            final var encrypted = EncryptedJWT.parse(string);
            encrypted.decrypt(decrypter);
            return extractFromClaims(encrypted.getJWTClaimsSet());
        } catch (ParseException | JOSEException e) {
            LOGGER.error(e.getMessage(), e);
            return null;
        }
    }
}
