package com.certidevs.service;

import com.certidevs.dtos.LoginResponse;
import com.certidevs.dtos.LoginUserDto;
import com.certidevs.dtos.RegisterUserDto;
import com.certidevs.model.User;
import com.certidevs.repository.UserRepository;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.apache.coyote.BadRequestException;
import org.springframework.dao.DataIntegrityViolationException;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.BadCredentialsException;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;

@Slf4j
@Service
@RequiredArgsConstructor
public class AuthenticationService {
    private final UserRepository userRepository;
    private final UserService userService;
    private final PasswordEncoder passwordEncoder;
    private final AuthenticationManager authenticationManager;

    public LoginResponse signup(RegisterUserDto request) throws BadRequestException {
        if (userRepository.existsByEmail(request.getEmail())) {
            log.error("SIGNUP ERROR -> El correo {} ya está en uso.", request.getEmail());
            throw new RuntimeException("Error al registrarse: el correo ya está en uso.");
        }

        var user = User
                .builder()
                .fullName(request.getFullName())
                .email(request.getEmail())
                .password(passwordEncoder.encode(request.getPassword()))
                .role("ROLE_USER")
                .build();

        user = userService.save(user);
        log.info("SIGNUP -> Usuario Registrado con exito");

        var jwt = JwtService.generateToken(user);
        return  LoginResponse.builder().token(jwt).build();
    }


    public LoginResponse login (LoginUserDto request) {
        try {
            authenticationManager.authenticate(
                    new UsernamePasswordAuthenticationToken(
                            request.getEmail(),
                            request.getPassword()));
            var user =  userRepository.findByEmail(request.getEmail())
                    .orElseThrow(() -> new UsernameNotFoundException("Invalid email or password"));
            var jwt = JwtService.generateToken(user);
            log.info("LOGIN -> Exitoso para el correo: {}", request.getEmail());
            return LoginResponse.builder().token(jwt).build();
        } catch (UsernameNotFoundException | BadCredentialsException e) {
            log.error("LOGIN ERROR -> Credenciales inválidas para el correo: {}. Detalles: {}", request.getEmail(), e.getMessage());
            throw new RuntimeException("Correo o contraseña incorrectos.");
        } catch (Exception e) {
            log.error("LOGIN ERROR -> Error inesperado en el intento de login para el correo: {}. Detalles: {}", request.getEmail(), e.getMessage());
            throw new RuntimeException("Error al intentar iniciar sesión. Por favor, intente nuevamente.");
        }
    }
}
