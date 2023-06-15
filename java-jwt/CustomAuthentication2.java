import org.springframework.security.core.Authentication;
import org.springframework.security.core.GrantedAuthority;

import java.util.Collection;
import java.util.List;

public class CustomAuthentication implements Authentication {

    private final UserDetails userDetails;
    private boolean authenticated;

    public CustomAuthentication(UserDetails userDetails) {
        this.userDetails = userDetails;
        this.authenticated = true;
    }

    @Override
    public Collection<? extends GrantedAuthority> getAuthorities() {
        List<Entitlement> userEntitlements = userDetails.getEntitlements();
        return userEntitlements.stream()
                .map(entitlement -> new SimpleGrantedAuthority(entitlement.getName()))
                .collect(Collectors.toList());
    }

    // Rest of the methods...

    // Additional method to access user entitlements
    public List<Entitlement> getEntitlements() {
        return userDetails.getEntitlements();
    }
}
