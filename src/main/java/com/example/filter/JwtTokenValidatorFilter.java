package com.example.filter;

//@Slf4j
//@RequiredArgsConstructor
//public class JwtTokenValidatorFilter extends OncePerRequestFilter {
//
//    private final EazyBankUserDetailsService userDetailsService;
//
//    @Override
//    protected void doFilterInternal(HttpServletRequest request, HttpServletResponse response, FilterChain filterChain) throws ServletException, IOException {
//        // Get JWT from 'Authorization' header
//        String jwt = request.getHeader(ApplicationConstants.JWT_HEADER);
//        if (jwt != null) {
//            try {
//                final var secret = getEnvironment().getProperty(ApplicationConstants.JWT_SECRET_KEY, ApplicationConstants.JWT_SECRET_VALUE);
//                final var secretKey = Keys.hmacShaKeyFor(secret.getBytes(StandardCharsets.UTF_8));
//                final var claims = Jwts.parser().verifyWith(secretKey).build().parseSignedClaims(jwt).getPayload();
//                final var username = String.valueOf(claims.get("username"));
////                final var authorities = String.valueOf(claims.get("authorities"));
//                final var authorizedUser = userDetailsService.loadUserByUsername(username);
//
//                Authentication authentication = new UsernamePasswordAuthenticationToken(authorizedUser, //username,
//                        null,
//                        authorizedUser.getAuthorities());
////                        AuthorityUtils.commaSeparatedStringToAuthorityList(authorities));
//
//                SecurityContextHolder.getContext().setAuthentication(authentication);
//            } catch (Exception e) {
//                log.error(e.getMessage(), e);
//                throw new BadCredentialsException("Invalid JWT token");
//            }
//        }
//
//        filterChain.doFilter(request, response);
//    }
//
//    @Override
//    protected boolean shouldNotFilter(HttpServletRequest request) throws ServletException {
//
//        return request.getServletPath().equals("/user");
//    }
//}
