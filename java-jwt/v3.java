import java.util.List;

public class User {
    private String username;
    private String sessionId;
    private List<Role> roles;

    // Constructors, getters, and setters
}

-------------------



public class Role {
    private String name;

    // Constructors, getters, and setters
}

----------------------

import org.springframework.stereotype.Service;

import java.util.Collections;
import java.util.List;

@Service
public class UserService {

    public User authenticate(String username, String sessionId) {
        // Perform authentication logic and retrieve roles for the user

        // For demo purposes, let's assume we have two hardcoded users with roles
        if (username.equals("admin") && sessionId.equals("123")) {
            Role adminRole = new Role("ADMIN");
            User adminUser = new User("admin", "123", Collections.singletonList(adminRole));
            return adminUser;
        } else if (username.equals("developer") && sessionId.equals("456")) {
            Role devRole = new Role("DEVELOPER");
            User devUser = new User("developer", "456", Collections.singletonList(devRole));
            return devUser;
        }

        // If user authentication fails, return null or throw an exception
        return null;
    }
}


-------------------------------



import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.authentication.BadCredentialsException;
import org.springframework.security.authentication.ReactiveAuthenticationManager;
import org.springframework.security.config.annotation.method.configuration.EnableReactiveMethodSecurity;
import org.springframework.security.config.annotation.web.reactive.EnableWebFluxSecurity;
import org.springframework.security.config.web.server.SecurityWebFiltersOrder;
import org.springframework.security.config.web.server.ServerHttpSecurity;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.web.server.SecurityWebFilterChain;
import org.springframework.security.web.server.authentication.AuthenticationWebFilter;
import org.springframework.security.web.server.authentication.ServerAuthenticationEntryPointFailureHandler;
import org.springframework.security.web.server.context.NoOpServerSecurityContextRepository;
import org.springframework.security.web.server.context.ServerSecurityContextRepository;
import org.springframework.security.web.server.util.matcher.ServerWebExchangeMatchers;
import reactor.core.publisher.Mono;

@Configuration
@EnableWebFluxSecurity
@EnableReactiveMethodSecurity
public class SecurityConfig {

    private static final String[] AUTH_WHITELIST = {
            "/api/login" // Add any public endpoints that don't require authentication
    };

    @Autowired
    private UserService userService;

    @Bean
    public PasswordEncoder passwordEncoder() {
        return new BCryptPasswordEncoder();
    }

    @Bean
    public SecurityWebFilterChain securityWebFilterChain(ServerHttpSecurity http) {
        return http
                .csrf().disable()
                .formLogin().disable()
                .httpBasic().disable()
                .authorizeExchange()
                .pathMatchers(AUTH_WHITELIST).permitAll()
                .anyExchange().authenticated()
                .and()
                .addFilterAt(authenticationWebFilter(), SecurityWebFiltersOrder.AUTHENTICATION)
                .build();
    }

    @Bean
    public AuthenticationWebFilter authenticationWebFilter() {
        AuthenticationWebFilter authenticationWebFilter = new AuthenticationWebFilter(authenticationManager());
        authenticationWebFilter.setServerAuthenticationConverter(exchange -> Mono.just(new JwtAuthenticationToken(parseTokenFromRequest(exchange))));
        authenticationWebFilter.setAuthenticationFailureHandler(new ServerAuthenticationEntryPointFailureHandler((exchange, e) -> Mono.error(e)));
        return authenticationWebFilter;
    }

    @Bean
    public ReactiveAuthenticationManager authenticationManager() {
        return authentication -> userService.authenticate(authentication.getPrincipal().toString(), authentication.getCredentials().toString())
                .map(user -> new JwtAuthenticationToken(user, user.getRoles()))
                .switchIfEmpty(Mono.error(new BadCredentialsException("Invalid credentials")));
    }

    @Bean
    public ServerSecurityContextRepository serverSecurityContextRepository() {
        return NoOpServerSecurityContextRepository.getInstance();
    }

    private String parseTokenFromRequest(ServerWebExchange exchange) {
        // Extract the JWT token from the request headers or cookies
        // Modify this method according to your token extraction mechanism
    }
}



------------------------------------------------




import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;
import reactor.core.publisher.Mono;

@RestController
@RequestMapping("/api")
public class MyController {

    @GetMapping("/onlyforadmin")
    @PreAuthorize("hasRole('ADMIN')")
    public Mono<String> onlyForAdminEndpoint() {
        return Mono.just("This endpoint is only accessible to users with the ADMIN role");
    }
}




------



import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;
import reactor.core.publisher.Mono;

@RestController
@RequestMapping("/api")
public class AuthController {

    @Autowired
    private UserService userService;

    @Autowired
    private JwtTokenUtil jwtTokenUtil;

    @PostMapping("/login")
    public Mono<String> login(@RequestBody LoginRequest loginRequest) {
        return Mono.fromCallable(() -> userService.authenticate(loginRequest.getUsername(), loginRequest.getSessionId()))
                .map(user -> {
                    if (user != null) {
                        String token = jwtTokenUtil.generateToken(user.getUsername(), user.getRolesAsString());
                        return token;
                    } else {
                        throw new BadCredentialsException("Invalid username or session ID");
                    }
                });
    }
}

class LoginRequest {
    private String username;
    private String sessionId;

    // Getters and Setters
}




----------------------------


import io.jsonwebtoken.Claims;
import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.SignatureAlgorithm;
import io.jsonwebtoken.security.Keys;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Component;

import javax.crypto.SecretKey;
import java.util.Date;

@Component
public class JwtTokenUtil {

    @Value("${jwt.secret}") // Add your own secret key in application.properties or application.yml
    private String secret;

    @Value("${jwt.expiration}") // Add the expiration time for the token in milliseconds
    private long expiration;

    public String generateToken(String username, String roles) {
        Date now = new Date();
        Date expiryDate = new Date(now.getTime() + expiration);

        SecretKey key = Keys.hmacShaKeyFor(secret.getBytes());

        return Jwts.builder()
                .setSubject(username)
                .claim("roles", roles)
                .setIssuedAt(now)
                .setExpiration(expiryDate)
                .signWith(key)
                .compact();
    }

    public Claims getClaimsFromToken(String token) {
        SecretKey key = Keys.hmacShaKeyFor(secret.getBytes());

        return Jwts.parserBuilder()
                .setSigningKey(key)
                .build()
                .parseClaimsJws(token)
                .getBody();
    }

    public boolean validateToken(String token) {
        SecretKey key = Keys.hmacShaKeyFor(secret.getBytes());

        try {
            Jwts.parserBuilder().setSigningKey(key).build().parseClaimsJws(token);
            return true;
        } catch (Exception ex) {
            return false;
        }
    }
}

















++++++++++++++++++++++++++++++++++


para lo de swagger 


import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.http.HttpMethod;
import org.springframework.security.authentication.ReactiveAuthenticationManager;
import org.springframework.security.authentication.UserDetailsRepositoryReactiveAuthenticationManager;
import org.springframework.security.config.annotation.method.configuration.EnableReactiveMethodSecurity;
import org.springframework.security.config.annotation.web.reactive.EnableWebFluxSecurity;
import org.springframework.security.config.web.server.SecurityWebFiltersOrder;
import org.springframework.security.config.web.server.ServerHttpSecurity;
import org.springframework.security.config.web.server.ServerSecurityHttpConfiguration;
import org.springframework.security.core.userdetails.MapReactiveUserDetailsService;
import org.springframework.security.core.userdetails.User;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.crypto.password.NoOpPasswordEncoder;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.web.server.SecurityWebFilterChain;
import org.springframework.security.web.server.context.NoOpServerSecurityContextRepository;
import org.springframework.security.web.server.context.ServerSecurityContextRepository;
import org.springframework.security.web.server.util.matcher.PathPatternParserServerWebExchangeMatcher;
import org.springframework.web.cors.CorsConfiguration;
import org.springframework.web.cors.reactive.CorsConfigurationSource;
import org.springframework.web.cors.reactive.UrlBasedCorsConfigurationSource;
import reactor.core.publisher.Mono;

@Configuration
@EnableWebFluxSecurity
@EnableReactiveMethodSecurity
public class SecurityConfig {

    private final JwtTokenUtil jwtTokenUtil;

    public SecurityConfig(JwtTokenUtil jwtTokenUtil) {
        this.jwtTokenUtil = jwtTokenUtil;
    }

    @Bean
    public SecurityWebFilterChain securityWebFilterChain(ServerHttpSecurity http) {
        return http
                .csrf().disable()
                .cors().configurationSource(corsConfigurationSource())
                .and()
                .authorizeExchange()
                .pathMatchers(HttpMethod.POST, "/api/login").permitAll()
                .pathMatchers(HttpMethod.GET, "/v3/api-docs/**", "/swagger-ui/**", "/swagger-ui.html").permitAll()
                .anyExchange().authenticated()
                .and()
                .addFilterAt(authenticationFilter(), SecurityWebFiltersOrder.HTTP_BASIC)
                .build();
    }

    private JwtAuthenticationFilter authenticationFilter() {
        ReactiveAuthenticationManager authenticationManager = authentication -> {
            if (authentication instanceof JwtAuthenticationToken) {
                return Mono.just(authentication);
            }
            return Mono.empty();
        };

        JwtAuthenticationFilter filter = new JwtAuthenticationFilter(authenticationManager, jwtTokenUtil);
        filter.setRequiresAuthenticationMatcher(
                new PathPatternParserServerWebExchangeMatcher("/api/**")
        );

        return filter;
    }

    @Bean
    public CorsConfigurationSource corsConfigurationSource() {
        CorsConfiguration corsConfig = new CorsConfiguration();
        corsConfig.addAllowedMethod(HttpMethod.GET);
        corsConfig.addAllowedMethod(HttpMethod.POST);
        corsConfig.addAllowedHeader("Authorization");
        corsConfig.setAllowCredentials(true);

        UrlBasedCorsConfigurationSource source = new UrlBasedCorsConfigurationSource();
        source.registerCorsConfiguration("/**", corsConfig);
        return source;
    }

    @Bean
    public ServerSecurityContextRepository serverSecurityContextRepository() {
        return NoOpServerSecurityContextRepository.getInstance();
    }

    @Bean
    public PasswordEncoder passwordEncoder() {
        return NoOpPasswordEncoder.getInstance();
    }

    @Bean
    public UserDetailsService userDetailsService() {
        UserDetails user = User.withUsername("admin")
                .password("password")
                .roles("ADMIN")
                .build();

        return new MapReactiveUserDetailsService(user);
    }
}



---------------------



import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import springfox.documentation.builders.RequestHandlerSelectors;
import springfox.documentation.service.ApiKey;
import springfox.documentation.spi.DocumentationType;
import springfox.documentation.spring.web.plugins.Docket;
import springfox.documentation.swagger.web.SecurityConfiguration;
import springfox.documentation.swagger.web.SecurityConfigurationBuilder;
import springfox.documentation.swagger.web.SecurityContext;
import springfox.documentation.swagger.web.SecurityContextBuilder;
import springfox.documentation.swagger2.annotations.EnableSwagger2WebFlux;

import java.util.Collections;

@Configuration
@EnableSwagger2WebFlux
public class SwaggerConfig {

    @Bean
    public Docket api() {
        return new Docket(DocumentationType.SWAGGER_2)
                .select()
                .apis(RequestHandlerSelectors.basePackage("com.example.api"))
                .build()
                .securitySchemes(Collections.singletonList(apiKey()))
                .securityContexts(Collections.singletonList(securityContext()));
    }

    @Bean
    public SecurityConfiguration security() {
        return SecurityConfigurationBuilder.builder().scopeSeparator(",")
                .additionalQueryStringParams(null)
                .useBasicAuthenticationWithAccessCodeGrant(false).build();
    }

    private ApiKey apiKey() {
        return new ApiKey("Bearer Token", "Authorization", "header");
    }

    private SecurityContext securityContext() {
        return SecurityContextBuilder.builder()
                .securityReferences(Collections.singletonList(defaultAuth()))
                .build();
    }

    private springfox.documentation.spi.service.contexts.SecurityReference defaultAuth() {
        return springfox.documentation.spi.service.contexts.SecurityReference.builder()
                .reference("Bearer Token")
                .scopes(new springfox.documentation.service.AuthorizationScope[0])
                .build();
    }
}

