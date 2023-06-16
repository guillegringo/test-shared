import org.springframework.security.authentication.ReactiveAuthenticationManager;
import org.springframework.security.core.Authentication;
import org.springframework.security.web.authentication.AbstractAuthenticationFilter;
import org.springframework.security.web.server.authentication.ServerAuthenticationConverter;
import org.springframework.security.web.server.authentication.ServerAuthenticationConverterSuccessHandler;
import org.springframework.security.web.server.util.matcher.ServerWebExchangeMatcher;
import org.springframework.security.web.server.util.matcher.ServerWebExchangeMatchers;
import org.springframework.web.server.ServerWebExchange;
import reactor.core.publisher.Mono;

public class JwtAuthenticationFilter extends AbstractAuthenticationFilter {

    private final ReactiveAuthenticationManager authenticationManager;
    private final ServerAuthenticationConverter bearerTokenConverter;

    public JwtAuthenticationFilter(ReactiveAuthenticationManager authenticationManager) {
        super(authenticationManager);
        this.authenticationManager = authenticationManager;
        this.bearerTokenConverter = new ServerBearerTokenAuthenticationConverter();
        setRequiresAuthenticationMatcher(ServerWebExchangeMatchers.anyExchange());
        setAuthenticationSuccessHandler(new ServerAuthenticationConverterSuccessHandler(bearerTokenConverter));
    }

    @Override
    public Mono<Void> filter(ServerWebExchange exchange, org.springframework.web.filter.reactive.HiddenHttpMethodFilter.WebFilterChain chain) {
        return super.filter(exchange, chain);
    }

    @Override
    protected Mono<Authentication> filter(ServerWebExchange exchange) {
        return bearerTokenConverter.convert(exchange)
                .flatMap(authentication -> authenticationManager.authenticate(authentication))
                .switchIfEmpty(Mono.empty());
    }
}
