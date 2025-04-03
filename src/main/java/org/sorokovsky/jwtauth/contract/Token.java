package org.sorokovsky.jwtauth.contract;

import java.time.Instant;
import java.util.UUID;

public record Token(UUID id, String email, Instant createdAt, Instant expiresAt) {
}
