package com.aminurdev.jwt.controller.rest.auth;

import com.aminurdev.jwt.domain.model.TokenRequest;
import com.aminurdev.jwt.domain.model.UserRequest;
import com.aminurdev.jwt.response.AuthResponse;
import com.aminurdev.jwt.service.AuthService;
import lombok.RequiredArgsConstructor;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.*;

@RestController
@RequestMapping("/api/v1/auth")
@RequiredArgsConstructor
public class AuthController {

    private final AuthService authService;

    @PostMapping("/register")
    public ResponseEntity<AuthResponse> register(@RequestBody UserRequest request)
    {
        return ResponseEntity.ok(authService.register(request));
    }

    @PostMapping("/login")
    public ResponseEntity<AuthResponse> login(@RequestBody UserRequest request)
    {
        return ResponseEntity.ok(authService.login(request));
    }

    @PostMapping("/refresh-token")
    public ResponseEntity<AuthResponse> refreshToken(@RequestBody TokenRequest tokenRequest)
    {
        return ResponseEntity.ok(authService.refreshToken(tokenRequest));
    }
}
