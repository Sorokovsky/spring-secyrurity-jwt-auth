package org.sorokovsky.jwtauth.contract;

public record ApiError(String message, int status) {
}
