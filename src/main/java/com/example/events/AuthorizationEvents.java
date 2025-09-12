package com.example.events;

import lombok.extern.slf4j.Slf4j;
import org.springframework.context.event.EventListener;
import org.springframework.security.authorization.event.AuthorizationDeniedEvent;
import org.springframework.stereotype.Component;

@Slf4j
@Component
public class AuthorizationEvents {

    @EventListener
    public void onFailure(AuthorizationDeniedEvent event) {
        log.error("Authorization failed for the user : {} due to : {}",
                event.getAuthentication().get().getName(),
                event.getAuthorizationResult().toString());
    }
}
