import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.ReactiveAuthenticationManager;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.web.server.authentication.AuthenticationWebFilter;
import org.springframework.security.web.server.authentication.ServerAuthenticationConverter;
import org.springframework.web.server.ServerWebExchange;
import reactor.core.publisher.Mono;

public class JwtAuthenticationFilter extends AuthenticationWebFilter {

    public JwtAuthenticationFilter(AuthenticationManager authenticationManager) {
        super((ReactiveAuthenticationManager) authenticationManager);
        setServerAuthenticationConverter(new JwtAuthenticationConverter());
    }
}

class JwtAuthenticationConverter implements ServerAuthenticationConverter {

    @Override
    public Mono<Authentication> convert(ServerWebExchange exchange) {
        // Extract the JWT token from the request and validate it
        // You can use the jjwt library or any other JWT library of your choice
        // Extract the user details from the token and create an Authentication object
        // For example:
        String jwtToken = extractJwtToken(exchange.getRequest());
        UserDetails userDetails = extractUserDetailsFromToken(jwtToken);
        Authentication authentication = new UsernamePasswordAuthenticationToken(
                userDetails, null, userDetails.getAuthorities());
        return Mono.just(authentication);
    }
}

class JwtAuthenticationProvider extends AbstractReactiveJwtAuthenticationManager {

    public JwtAuthenticationProvider() {
        setJwtDecoder(jwtDecoder());
    }

    private ReactiveJwtDecoder jwtDecoder() {
        // Create a JWT decoder with your secret or public key
        // For example:
        String secretKey = "your-secret-key";
        JwtParser jwtParser = Jwts.parserBuilder()
                .setSigningKey(Keys.hmacShaKeyFor(secretKey.getBytes(StandardCharsets.UTF_8)))
                .build();
        return (token) -> Mono.just(jwtParser.parseClaimsJws(token.getTokenValue()).getBody());
    }
}
