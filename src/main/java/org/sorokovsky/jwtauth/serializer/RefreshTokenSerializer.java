package org.sorokovsky.jwtauth.serializer;

import com.nimbusds.jose.*;
import com.nimbusds.jwt.EncryptedJWT;
import com.nimbusds.jwt.JWTClaimsSet;
import lombok.Setter;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.sorokovsky.jwtauth.model.TokenModel;

import java.util.Date;
import java.util.function.Function;

public class RefreshTokenSerializer implements Function<TokenModel, String> {
    private static final Logger LOGGER = LoggerFactory.getLogger(RefreshTokenSerializer.class);

    private final JWEEncrypter encrypter;
    @Setter
    private JWEAlgorithm algorithm = JWEAlgorithm.DIR;

    @Setter
    private EncryptionMethod method = EncryptionMethod.A128GCM;

    public RefreshTokenSerializer(JWEEncrypter encrypter) {
        this.encrypter = encrypter;
    }

    @Override
    public String apply(TokenModel tokenModel) {
        var header = new JWEHeader.Builder(algorithm, method)
                .keyID(tokenModel.id().toString())
                .build();
        var claims = new JWTClaimsSet.Builder()
                .jwtID(tokenModel.id().toString())
                .subject(tokenModel.email())
                .issueTime(Date.from(tokenModel.createdAt()))
                .expirationTime(Date.from(tokenModel.expiresAt()))
                .build();
        var encrypted = new EncryptedJWT(header, claims);
        try {
            encrypted.encrypt(encrypter);
            return encrypted.serialize();
        } catch (JOSEException e) {
            LOGGER.error(e.getMessage(), e);
        }
        return null;
    }
}
