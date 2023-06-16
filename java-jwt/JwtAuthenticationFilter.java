public class JwtAuthenticationFilter extends AbstractAuthenticationFilter {

    private final ReactiveAuthenticationManager authenticationManager;

    public JwtAuthenticationFilter(ReactiveAuthenticationManager authenticationManager) {
        super(authenticationManager);
        this.authenticationManager = authenticationManager;
    }

    @Override
    public Mono<Void> filter(ServerWebExchange exchange, WebFilterChain chain) {
        return super.filter(exchange, chain);
    }

    @Override
    protected Mono<Authentication> filterInternal(ServerWebExchange exchange) {
        return ServerHttpBearerAuthenticationConverter
                .authenticate(exchange)
                .flatMap(authentication -> authenticationManager.authenticate(authentication))
                .switchIfEmpty(Mono.empty());
    }

}
