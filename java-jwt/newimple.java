@RestController
@RequestMapping("/auth")
public class AuthenticationController {

    private final JwtTokenProvider jwtTokenProvider;

    public AuthenticationController(JwtTokenProvider jwtTokenProvider) {
        this.jwtTokenProvider = jwtTokenProvider;
    }

    @PostMapping("/login")
    public Mono<ResponseEntity<?>> login(@RequestHeader("SM_USER") String username,
                                         @RequestHeader("SM_SESSIONID") String sessionId) {
        // Retrieve user information and session data from Siteminder
        // Replace this with your logic to fetch user information from Siteminder

        // Example: User details are extracted from the SM_USER header

        // Perform additional validation or data retrieval if needed
        // ...

        // Generate JWT token
        String token = jwtTokenProvider.createToken(username, List.of("ROLE_ADMIN"));

        // Return the token in the response
        return Mono.just(ResponseEntity.ok(new AuthenticationResponse(token)));
    }
}


-------------


@Component
public class JwtTokenProvider {

    private final String secret;
    private final long validityInMilliseconds;

    public JwtTokenProvider(@Value("${jwt.secret}") String secret,
                            @Value("${jwt.expiration}") long validityInSeconds) {
        this.secret = secret;
        this.validityInMilliseconds = validityInSeconds * 1000;
    }

    public String createToken(String username, List<String> roles) {
        Claims claims = Jwts.claims().setSubject(username);
        claims.put("roles", roles);

        Date now = new Date();
        Date validity = new Date(now.getTime() + validityInMilliseconds);

        return Jwts.builder()
                .setClaims(claims)
                .setIssuedAt(now)
                .setExpiration(validity)
                .signWith(SignatureAlgorithm.HS256, secret)
                .compact();
    }
}



---------------


public class AuthenticationResponse {

    private String token;

    public AuthenticationResponse(String token) {
        this.token = token;
    }

    public String getToken() {
        return token;
    }

    // Add setter if needed
}


-----------------



@Configuration
public class SecurityConfig {

    @Value("${jwt.secret}")
    private String jwtSecret;

    @Bean
    public SecurityWebFilterChain securityWebFilterChain(ServerHttpSecurity http) {
        return http.csrf().disable()
                .authorizeExchange()
                .pathMatchers("/public/**").permitAll()
                .anyExchange().authenticated()
                .and()
                .addFilterAt(jwtAuthenticationFilter(), SecurityWebFiltersOrder.AUTHENTICATION)
                .exceptionHandling()
                .authenticationEntryPoint((swe, e) -> Mono.fromRunnable(() -> swe.getResponse().setStatusCode(HttpStatus.UNAUTHORIZED)))
                .accessDeniedHandler((swe, e) -> Mono.fromRunnable(() -> swe.getResponse().setStatusCode(HttpStatus.FORBIDDEN)))
                .and()
                .build();
    }

    @Bean
    public JwtAuthenticationFilter jwtAuthenticationFilter() {
        return new JwtAuthenticationFilter(jwtAuthenticationManager());
    }

    @Bean
    public ReactiveAuthenticationManager jwtAuthenticationManager() {
        return new JwtAuthenticationManager(jwtSecret);
    }
}



--------------------------


public class JwtAuthenticationFilter extends AbstractAuthenticationFilter {

    private final ReactiveAuthenticationManager authenticationManager;

    public JwtAuthenticationFilter(ReactiveAuthenticationManager authenticationManager) {
        super(exchange -> Mono.empty());
        this.authenticationManager = authenticationManager;
    }

    @Override
    public Mono<Void> filter(ServerWebExchange exchange, WebFilterChain chain) {
        return getAuthentication(exchange)
                .flatMap(authentication -> authenticate(exchange, chain, authentication))
                .switchIfEmpty(chain.filter(exchange));
    }

    private Mono<Authentication> getAuthentication(ServerWebExchange exchange) {
        return Mono.justOrEmpty(exchange.getRequest().getHeaders().getFirst(HttpHeaders.AUTHORIZATION))
                .filter(header -> header.startsWith("Bearer "))
                .map(header -> header.substring(7))
                .map(JwtAuthenticationToken::new);
    }

    private Mono<Void> authenticate(ServerWebExchange exchange, WebFilterChain chain, Authentication authentication) {
        return authenticationManager.authenticate(authentication)
                .flatMap(auth -> onAuthenticationSuccess(exchange, chain, auth))
                .onErrorResume(AuthenticationException.class, e -> onAuthenticationFailure(exchange, e));
    }

    private Mono<Void> onAuthenticationSuccess(ServerWebExchange exchange, WebFilterChain chain, Authentication authentication) {
        SecurityContext context = new SecurityContextImpl(authentication);
        exchange.getAttributes().put(SecurityContext.class.getName(), context);
        return chain.filter(exchange);
    }

    private Mono<Void> onAuthenticationFailure(ServerWebExchange exchange, AuthenticationException exception) {
        exchange.getResponse().setStatusCode(HttpStatus.UNAUTHORIZED);
        return exchange.getResponse().setComplete();
    }
}


