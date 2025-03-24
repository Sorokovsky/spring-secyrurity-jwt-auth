package org.sorokovsky.jwtauth.deserializer;

import com.nimbusds.jose.JOSEException;
import com.nimbusds.jose.JWEDecrypter;
import com.nimbusds.jwt.EncryptedJWT;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.sorokovsky.jwtauth.model.TokenModel;

import java.text.ParseException;
import java.util.UUID;
import java.util.function.Function;

public class RefreshTokenDeserializer implements Function<String, TokenModel> {
    private static final Logger LOGGER = LoggerFactory.getLogger(RefreshTokenDeserializer.class);

    private final JWEDecrypter decrypter;

    public RefreshTokenDeserializer(JWEDecrypter decrypter) {
        this.decrypter = decrypter;
    }

    @Override
    public TokenModel apply(String s) {
        try {
            var encrypted = EncryptedJWT.parse(s);
            encrypted.decrypt(decrypter);
            var claims = encrypted.getJWTClaimsSet();
            return new TokenModel(
                    UUID.fromString(claims.getJWTID()),
                    claims.getSubject(),
                    claims.getIssueTime().toInstant(),
                    claims.getExpirationTime().toInstant()
            );
        } catch (ParseException | JOSEException e) {
            LOGGER.error(e.getMessage(), e);
        }
        return null;
    }
}
