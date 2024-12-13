package acc.br.login.security;

import javax.sql.DataSource;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.config.annotation.authentication.builders.AuthenticationManagerBuilder;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configuration.WebSecurityConfiguration;
import org.springframework.security.core.userdetails.User;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.provisioning.InMemoryUserDetailsManager;
import org.springframework.security.web.SecurityFilterChain;

import acc.br.login.repository.UserRepository;

/**
 * Security configuration class for setting up security rules.
 */
@Configuration
@EnableWebSecurity
public class SecurityConfig extends WebSecurityConfiguration {

	@Autowired
    private DataSource dataSource;
    /**
     * Bean for password encoding using BCrypt.
     * @return PasswordEncoder
     */
    @Bean
    public PasswordEncoder passwordEncoder() {
        return new BCryptPasswordEncoder();
    }
    
    protected void configure(AuthenticationManagerBuilder auth) throws Exception {
        auth.jdbcAuthentication()
            .dataSource(dataSource)
            .passwordEncoder(passwordEncoder())
            .usersByUsernameQuery("SELECT username, password, enabled FROM users WHERE username = ?")
            .authoritiesByUsernameQuery("SELECT username, authority FROM authorities WHERE username = ?");
    }
    

	protected void configure(HttpSecurity http) throws Exception {
    	 http
         .authorizeHttpRequests(authorize -> authorize
                 .requestMatchers("/login", "/register", "/h2", "/public/**").permitAll()  // Allow unauthenticated access to login and public pages
                 .requestMatchers("/admin/**").hasRole("ADMIN")       // Restrict access to /admin/** to ADMIN role only
                 .requestMatchers("/user/**").hasAnyRole("USER", "ADMIN")  // Allow access to /user/** for USER and ADMIN roles
                 .anyRequest().authenticated()                        // All other requests require authentication
         )
         .formLogin(form -> form
                 .loginPage("/login")                                // Custom login page
                 .defaultSuccessUrl("/home", true)                   // Redirect to home after successful login
                 .permitAll()                                        // Allow all to access login page
         )
         .logout(logout -> logout
                 .permitAll()                                        // Allow all to log out
         );
    }

    
    @Bean
    public UserDetailsService userDetailsService(UserRepository userRepository) {
        return username -> userRepository.findByUsername(username)
                .map(user -> org.springframework.security.core.userdetails.User
                        .withUsername(user.getUsername())
                        .password(user.getPassword())
                        .roles(user.getRoles().toArray(new String[0]))
                        .build())
                .orElseThrow(() -> new UsernameNotFoundException("Usuário não encontrado!"));
    }


    /**
     * Bean for configuring HTTP security with authorization and authentication rules.
     * @param http HttpSecurity
     * @return SecurityFilterChain
     * @throws Exception
     */
    @Bean
    public SecurityFilterChain securityFilterChain(HttpSecurity http) throws Exception {
        http
                .authorizeHttpRequests(authorize -> authorize
                        .requestMatchers("/login", "/register", "/h2", "/public/**").permitAll()  // Allow unauthenticated access to login and public pages
                        .requestMatchers("/admin/**").hasRole("ADMIN")       // Restrict access to /admin/** to ADMIN role only
                        .requestMatchers("/user/**").hasAnyRole("USER", "ADMIN")  // Allow access to /user/** for USER and ADMIN roles
                        .anyRequest().authenticated()                        // All other requests require authentication
                )
                .formLogin(form -> form
                        .loginPage("/login")                                // Custom login page
                        .defaultSuccessUrl("/home", true)                   // Redirect to home after successful login
                        .permitAll()                                        // Allow all to access login page
                )
                .logout(logout -> logout
                        .permitAll()                                        // Allow all to log out
                );

        return http.build();
    }
}