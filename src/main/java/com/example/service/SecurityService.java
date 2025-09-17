package com.example.service;

import com.example.dto.AuthorizedUser;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.stereotype.Service;

@Service
public class SecurityService {

    public boolean canAccessUserData(Long userId) {
        Authentication auth = SecurityContextHolder.getContext().getAuthentication();

        if (auth == null)
            return false;

        AuthorizedUser userDetails = (AuthorizedUser) auth.getPrincipal();

        return userDetails.getId().equals(userId);
//               auth.getAuthorities().stream()
//                       .anyMatch(a -> a.getAuthority().equals("ROLE_ADMIN"));
    }

}
