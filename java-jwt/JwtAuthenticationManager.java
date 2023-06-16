public class JwtAuthenticationManager implements ReactiveAuthenticationManager {

    @Override
    public Mono<Authentication> authenticate(Authentication authentication) {
        if (authentication instanceof JwtAuthenticationToken) {
            JwtAuthenticationToken jwtAuthenticationToken = (JwtAuthenticationToken) authentication;
            String token = jwtAuthenticationToken.getToken();

            if (isValidToken(token)) {
                // Extraer información del token y construir el objeto de autenticación
                // Puedes usar una biblioteca como jjwt para validar y decodificar el token
                // y luego construir un objeto de autenticación con los detalles necesarios

                // Ejemplo:
                String username = extractUsernameFromToken(token);
                List<GrantedAuthority> authorities = extractAuthoritiesFromToken(token);

                UserDetails userDetails = new User(username, "", authorities);
                return Mono.just(new UsernamePasswordAuthenticationToken(userDetails, token, authorities));
            } else {
                return Mono.empty(); // Token inválido, la autenticación falla
            }
        }

        return Mono.empty(); // No se puede autenticar con otros tipos de Authentication
    }

    private boolean isValidToken(String token) {
        // Lógica para validar la firma y la validez del token JWT
        // Puedes usar una biblioteca como jjwt para realizar estas validaciones
        // y devolver true si el token es válido, o false si no lo es
    }

    private String extractUsernameFromToken(String token) {
        // Lógica para extraer el nombre de usuario del token JWT
        // Puedes usar una biblioteca como jjwt para decodificar el token y obtener el nombre de usuario
    }

    private List<GrantedAuthority> extractAuthoritiesFromToken(String token) {
        // Lógica para extraer los roles o autorizaciones del token JWT
        // Puedes usar una biblioteca como jjwt para decodificar el token y obtener los roles o autorizaciones
    }
}
