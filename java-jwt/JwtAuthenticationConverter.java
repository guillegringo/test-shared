class JwtAuthenticationConverter implements ServerAuthenticationConverter {

    @Override
    public Mono<Authentication> convert(ServerWebExchange exchange) {
        // Extract the JWT token from the request and validate it
        // You can use the jjwt library or any other JWT library of your choice
        // Extract the user details from the token and create a CustomAuthentication object
        // For example:
        String jwtToken = extractJwtToken(exchange.getRequest());
        UserDetails userDetails = extractUserDetailsFromToken(jwtToken);
        Authentication authentication = new CustomAuthentication(userDetails);
        return Mono.just(authentication);
    }
}
