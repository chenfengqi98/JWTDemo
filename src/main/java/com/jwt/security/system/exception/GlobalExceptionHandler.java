package com.jwt.security.system.exception;

import org.springframework.http.HttpStatus;
import org.springframework.web.bind.annotation.ExceptionHandler;
import org.springframework.web.bind.annotation.ResponseStatus;

import java.security.SignatureException;

public class GlobalExceptionHandler {

    @ExceptionHandler(value = UserNameAlreadyExistException.class)
    @ResponseStatus(HttpStatus.BAD_REQUEST)
    public ErrorMessage handleUserNameAlreadyExistException(UserNameAlreadyExistException exception){
        return new ErrorMessage(HttpStatus.BAD_REQUEST.value(), exception.getMessage());
    }

    @ExceptionHandler(value = SignatureException.class)
    @ResponseStatus(HttpStatus.BAD_REQUEST)
    public ErrorMessage handleSignatureException(SignatureException e){
        return new ErrorMessage(HttpStatus.UNAUTHORIZED.value(),e.getMessage());
    }

}
