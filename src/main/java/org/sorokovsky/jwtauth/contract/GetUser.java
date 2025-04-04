package org.sorokovsky.jwtauth.contract;

import java.time.LocalDateTime;

public record GetUser(long id, String email, LocalDateTime createdAt, LocalDateTime updatedAt) {
}
