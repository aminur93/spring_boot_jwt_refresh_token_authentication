package com.aminurdev.jwt.service;

import com.aminurdev.jwt.domain.entity.Token;
import com.aminurdev.jwt.domain.entity.TokenType;
import com.aminurdev.jwt.domain.entity.User;
import com.aminurdev.jwt.domain.model.TokenRequest;
import com.aminurdev.jwt.domain.model.UserRequest;
import com.aminurdev.jwt.domain.repository.TokenRepository;
import com.aminurdev.jwt.domain.repository.UserRepository;
import com.aminurdev.jwt.response.AuthResponse;
import lombok.RequiredArgsConstructor;
import org.springframework.http.HttpStatus;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;

import java.util.HashMap;

@Service
@RequiredArgsConstructor
public class AuthService {

    private final UserRepository userRepository;

    private final TokenRepository tokenRepository;

    private final PasswordEncoder passwordEncoder;

    private final JwtService jwtService;

    private final AuthenticationManager authenticationManager;

    public AuthResponse register(UserRequest request)
    {
        AuthResponse response = new AuthResponse();

        try{

            User user = new User();

            user.setName(request.getName());
            user.setEmail(request.getEmail());
            user.setPassword(passwordEncoder.encode(request.getPassword()));
            user.setRole(request.getRole());

            User userResult = userRepository.save(user);

            if (userResult.getId() > 0)
            {
                User responseData = new User();

                responseData.setName(userResult.getName());
                responseData.setEmail(userResult.getEmail());
                responseData.setRole(userResult.getRole());
                responseData.setCreatedAt( userResult.getCreatedAt());
                responseData.setUpdatedAt(userResult.getUpdatedAt());

                response.setUser(responseData);
                response.setMessage("User store successful");
                response.setStatusCode(HttpStatus.CREATED.value());
            }

        }catch (Exception e){
            response.setStatusCode(HttpStatus.INTERNAL_SERVER_ERROR.value());
            response.setMessage(e.getMessage());
        }

        return response;
    }

    public AuthResponse login(UserRequest request)
    {
        AuthResponse response = new AuthResponse();

        try{

            authenticationManager.authenticate(
                    new UsernamePasswordAuthenticationToken(
                            request.getEmail(),
                            request.getPassword()
                    )
            );

            User user = userRepository.findByEmail(request.getEmail()).orElseThrow(() -> new RuntimeException("User not found"));

            String jwtToken = jwtService.generateToken(user);

            revokedAllUserTokens(user);

            saveUserToken(user, jwtToken);

            String refreshToken = jwtService.generateRefreshToken(new HashMap<>(), user);

            if (user.getId() > 0)
            {
                User responseData = new User();

                responseData.setName(user.getName());
                responseData.setEmail(user.getEmail());
                responseData.setRole(user.getRole());
                responseData.setCreatedAt( user.getCreatedAt());
                responseData.setUpdatedAt(user.getUpdatedAt());

                response.setUser(responseData);
                response.setMessage("Login successful");
                response.setStatusCode(HttpStatus.OK.value());
                response.setToken(jwtToken);
                response.setRefreshToken(refreshToken);
                response.setExpiration("24Hr");
            }

        }catch (Exception e){
            response.setStatusCode(HttpStatus.INTERNAL_SERVER_ERROR.value());
            response.setMessage(e.getMessage());
        }

        return response;
    }

    public AuthResponse refreshToken(TokenRequest tokenRequest)
    {
        AuthResponse response = new AuthResponse();

        try{

            String userEmail = jwtService.extractUsername(tokenRequest.getRefreshToken());

            User user = userRepository.findByEmail(userEmail).orElseThrow(() -> new RuntimeException("User not found"));

            if (jwtService.isTokenValid(tokenRequest.getRefreshToken(), user)) {

                var jwt = jwtService.generateToken(user);

                revokedAllUserTokens(user);

                saveUserToken(user, jwt);

                response.setStatusCode(200);
                response.setToken(jwt);
                response.setRefreshToken(tokenRequest.getRefreshToken());
                response.setExpiration("24Hr");
                response.setMessage("Successfully Refreshed Token");
            }

        }catch (Exception e){
            response.setStatusCode(HttpStatus.INTERNAL_SERVER_ERROR.value());
            response.setMessage(e.getMessage());
        }

        return  response;
    }

    private void revokedAllUserTokens(User user)
    {
        var validUserTokens = tokenRepository.findAllValidTokensByUser(user.getId());

        if ((validUserTokens.isEmpty()))
        {
            return;
        }

        validUserTokens.forEach(t -> {
            t.setExpired(1);
            t.setRevoked(1);
        });

        tokenRepository.saveAll(validUserTokens);
    }

    public void saveUserToken(User user, String jwtToken)
    {
        Token token = new Token();

        token.setUser(user);
        token.setToken(jwtToken);
        token.setTokenType(TokenType.BEARER);
        token.setExpired(0);
        token.setRevoked(0);

        tokenRepository.save(token);
    }
}
