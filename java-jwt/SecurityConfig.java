import org.springframework.context.annotation.Configuration;
import org.springframework.http.HttpMethod;
import org.springframework.security.config.annotation.method.configuration.EnableGlobalMethodSecurity;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configuration.WebSecurityConfigurerAdapter;

@Configuration
@EnableWebSecurity
@EnableGlobalMethodSecurity(prePostEnabled = true)
public class SecurityConfig extends WebSecurityConfigurerAdapter {

    @Override
    protected void configure(HttpSecurity http) throws Exception {
        http.csrf().disable()
            .authorizeExchange()
            .pathMatchers(HttpMethod.POST, "/api/authenticate").permitAll()
            .anyExchange().authenticated()
            .and()
            .addFilter(new JwtAuthenticationFilter(authenticationManager()))
            .exceptionHandling()
            .and()
            .authenticationProvider(new JwtAuthenticationProvider());
    }
}
