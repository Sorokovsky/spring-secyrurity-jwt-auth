package org.sorokovsky.jwtauth.serializer;

import com.nimbusds.jose.*;
import com.nimbusds.jwt.EncryptedJWT;
import lombok.RequiredArgsConstructor;
import lombok.Setter;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.sorokovsky.jwtauth.contract.Token;

@RequiredArgsConstructor
@Setter
public class DefaultRefreshTokenSerializer extends AbstractTokenSerializer {
    private static final Logger LOGGER = LoggerFactory.getLogger(DefaultRefreshTokenSerializer.class);

    private final JWEEncrypter encrypter;
    private JWEAlgorithm algorithm = JWEAlgorithm.DIR;
    private EncryptionMethod method = EncryptionMethod.A128GCM;

    @Override
    public String apply(Token token) {
        final var header = new JWEHeader.Builder(algorithm, method)
                .keyID(token.id().toString())
                .build();
        final var claims = convertToClaims(token);
        final var encrypted = new EncryptedJWT(header, claims);
        try {
            encrypted.encrypt(encrypter);
            return encrypted.serialize();
        } catch (JOSEException e) {
            LOGGER.error(e.getMessage(), e);
            return null;
        }
    }
}
