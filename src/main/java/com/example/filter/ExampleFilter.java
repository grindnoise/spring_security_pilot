package com.example.filter;

import jakarta.servlet.*;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import org.springframework.http.HttpHeaders;
import org.springframework.security.authentication.BadCredentialsException;

import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.util.Base64;
import java.util.Locale;

/**
 * Example of filtering request header
 */
public class ExampleFilter implements Filter {

    private static final String KEYWORD = "test";

    @Override
    public void doFilter(ServletRequest request, ServletResponse response, FilterChain chain) throws IOException, ServletException {
        // Cast needed
        HttpServletRequest req = (HttpServletRequest) request;
        HttpServletResponse res = (HttpServletResponse) response;
        // Get Authorization header
        String header = req.getHeader(HttpHeaders.AUTHORIZATION);
        if (header != null) {
            // Extract and decode data
            header = header.trim();
            if (header.startsWith("Basic ")) {
                // decode() uses ISO_8859_1
//                var decodedBytes = Base64.getDecoder().decode(header.split(" ")[1]);

                // Explicitly set utf-8
                final var encodedBytes = header.substring(6).getBytes(StandardCharsets.UTF_8);
                try {
                    final var decodedBytes = Base64.getDecoder().decode(encodedBytes);
                    final var decodedString = new String(decodedBytes, StandardCharsets.UTF_8);

                    final var credentials = decodedString.split(":");
                    if (credentials.length == 2) {
                        if (credentials[0].toLowerCase(Locale.ROOT).contains(KEYWORD)) {
                            res.setStatus(HttpServletResponse.SC_BAD_REQUEST);
                            return;
                        }
                    }
                } catch (IllegalArgumentException e) {
                    throw new BadCredentialsException("Failed to decode basic authentication token");
                }
            }
        }
        chain.doFilter(request, response);
    }
}
