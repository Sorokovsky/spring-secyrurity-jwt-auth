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

public class AccessTokenSerializer implements Function<TokenModel, String> {
    private static final Logger LOGGER = LoggerFactory.getLogger(AccessTokenSerializer.class);

    private final JWEEncrypter encryptor;
    @Setter
    private JWEAlgorithm algorithm = JWEAlgorithm.DIR;
    @Setter
    private EncryptionMethod method = EncryptionMethod.A128GCM;

    public AccessTokenSerializer(JWEEncrypter encryptor) {
        this.encryptor = encryptor;
    }

    @Override
    public String apply(TokenModel tokenModel) {
        var header = new JWEHeader.Builder(algorithm, method)
                .keyID(tokenModel.id().toString())
                .build();
        var claims = new JWTClaimsSet.Builder()
                .jwtID(tokenModel.id().toString())
                .issueTime(Date.from(tokenModel.createdAt()))
                .expirationTime(Date.from(tokenModel.expiresAt()))
                .subject(tokenModel.email())
                .build();
        var encrypted = new EncryptedJWT(header, claims);
        try {
            encrypted.encrypt(encryptor);
            return encrypted.serialize();
        } catch (JOSEException e) {
            LOGGER.error(e.getMessage(), e);
        }
        return null;
    }
}
