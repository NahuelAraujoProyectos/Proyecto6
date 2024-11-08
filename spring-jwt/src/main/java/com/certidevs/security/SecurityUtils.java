package com.certidevs.security;

import com.certidevs.model.User;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.core.userdetails.UserDetails;

public class SecurityUtils {

    // Método para obtener el usuario autenticado desde el contexto de seguridad
    public static User getAuthenticatedUser() {
        Object principal = SecurityContextHolder.getContext().getAuthentication().getPrincipal();

        if (principal instanceof UserDetails) {
            // Si el principal es una instancia de UserDetails, lo casteamos y obtenemos el email o la información deseada
            return (User) principal;
        } else {
            // Si no hay un usuario autenticado, devolvemos null
            return null;
        }
    }
}