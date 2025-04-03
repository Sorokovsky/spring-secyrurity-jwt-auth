package org.sorokovsky.jwtauth.deserializer;

import com.nimbusds.jwt.JWTClaimsSet;
import org.sorokovsky.jwtauth.contract.Token;

import java.util.UUID;

public abstract class AbstractTokenDeserializer implements TokenDeserializer {
    protected Token extractFromClaims(JWTClaimsSet claimsSet) {
        return new Token(
                UUID.fromString(claimsSet.getJWTID()),
                claimsSet.getSubject(),
                claimsSet.getIssueTime().toInstant(),
                claimsSet.getExpirationTime().toInstant()
        );
    }
}
