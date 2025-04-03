package org.sorokovsky.jwtauth.serializer;

import com.nimbusds.jwt.JWTClaimsSet;
import org.sorokovsky.jwtauth.contract.Token;

import java.util.Date;

public abstract class AbstractTokenSerializer implements TokenSerializer {
    protected JWTClaimsSet convertToClaims(Token token) {
        return new JWTClaimsSet.Builder()
                .jwtID(token.id().toString())
                .subject(token.email())
                .issueTime(Date.from(token.createdAt()))
                .expirationTime(Date.from(token.expiresAt()))
                .build();
    }
}
