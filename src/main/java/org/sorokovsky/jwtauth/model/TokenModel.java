package org.sorokovsky.jwtauth.model;

import java.time.Instant;
import java.util.UUID;

public record TokenModel(UUID id, String email, Instant createdAt, Instant expiresAt) {
}
