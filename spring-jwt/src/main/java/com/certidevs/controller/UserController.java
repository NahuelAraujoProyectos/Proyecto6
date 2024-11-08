package com.certidevs.controller;

import com.certidevs.model.User;
import com.certidevs.security.SecurityUtils;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

@Slf4j
@RequestMapping
@RestController
@RequiredArgsConstructor
public class UserController {
    @GetMapping("/me")
    public ResponseEntity<User> getAuthenticatedUser() {
        User user = SecurityUtils.getAuthenticatedUser();

        if (user != null) {
            // Log exitoso
            return ResponseEntity.ok(user); // Devolver el usuario en la respuesta
        } else {
            // Log de error
            return ResponseEntity.status(401).body(null); // Retornar 401 si no está autenticado
        }
    }
}
