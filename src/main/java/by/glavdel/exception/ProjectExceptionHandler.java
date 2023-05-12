package by.glavdel.exception;

import lombok.extern.slf4j.Slf4j;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.ControllerAdvice;
import org.springframework.web.bind.annotation.ExceptionHandler;
import org.springframework.web.servlet.mvc.method.annotation.ResponseEntityExceptionHandler;

@Slf4j
@ControllerAdvice
public class ProjectExceptionHandler extends ResponseEntityExceptionHandler {

    @ExceptionHandler(NotFoundException.class)
    public ResponseEntity<Object> handleNotFoundException(NotFoundException ex) {
        ErrorDto errorDto = new ErrorDto(ExceptionMessageConstant.WRONG_REQUEST + ex.getMessage());
        HttpStatus status = HttpStatus.NOT_FOUND;
        log.warn(errorDto.getMessage());
        return ResponseEntity.status(status).body(errorDto);
    }

    @ExceptionHandler(AuthenticatException.class)
    public ResponseEntity<Object> handleAuthenticatException(AuthenticatException ex) {
        ErrorDto errorDto = new ErrorDto(ex.getMessage());
        HttpStatus status = HttpStatus.UNAUTHORIZED;
        log.warn(errorDto.getMessage());
        return ResponseEntity.status(status).body(errorDto);
    }
}
