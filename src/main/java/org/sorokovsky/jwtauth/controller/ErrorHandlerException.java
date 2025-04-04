package org.sorokovsky.jwtauth.controller;

import jakarta.validation.ConstraintViolation;
import jakarta.validation.ConstraintViolationException;
import org.sorokovsky.jwtauth.contract.ApiError;
import org.sorokovsky.jwtauth.exception.HttpException;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.ControllerAdvice;
import org.springframework.web.bind.annotation.ExceptionHandler;

import java.util.stream.Collectors;

@ControllerAdvice
public class ErrorHandlerException {
    @ExceptionHandler({HttpException.class})
    public ResponseEntity<ApiError> handleHttpException(HttpException exception) {
        final var apiError = new ApiError(exception.getMessage(), exception.getHttpStatus().value());
        return ResponseEntity.status(apiError.status()).body(apiError);
    }

    @ExceptionHandler({ConstraintViolationException.class})
    public ResponseEntity<ApiError> handleConstraintViolationException(ConstraintViolationException exception) {
        final var message = exception.getConstraintViolations().stream()
                .map(ConstraintViolation::getMessage).collect(Collectors.joining(", "));
        final var apiError = new ApiError(message, HttpStatus.BAD_REQUEST.value());
        return ResponseEntity.status(apiError.status()).body(apiError);
    }
}
