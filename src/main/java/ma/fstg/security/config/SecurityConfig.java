package ma.fstg.security.config;

import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.core.userdetails.User;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.provisioning.InMemoryUserDetailsManager;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security.web.authentication.AuthenticationSuccessHandler;

/**
 * Configuration de la securite de l'application.
 * <p>
 * Tout est centralise ici : la chaine de filtres, les utilisateurs en memoire,
 * l'encodeur de mots de passe et la page de connexion personnalisee. Les deux
 * gestionnaires de succes et d'echec alimentent le journal des connexions.
 */
@Configuration
@EnableWebSecurity
public class SecurityConfig {

    /**
     * Encodage des mots de passe.
     * <p>
     * BCrypt genere un sel aleatoire a chaque appel : deux utilisateurs ayant le
     * meme mot de passe n'obtiennent donc pas le meme hash.
     *
     * @return l'encodeur partage
     */
    @Bean
    public PasswordEncoder passwordEncoder() {
        return new BCryptPasswordEncoder();
    }

    /**
     * Utilisateurs declares en memoire.
     *
     * @param passwordEncoder encodeur applique aux mots de passe
     * @return le gestionnaire d'utilisateurs
     */
    @Bean
    public UserDetailsService userDetailsService(PasswordEncoder passwordEncoder) {
        UserDetails user = User.withUsername("user")
                .password(passwordEncoder.encode("1111"))
                .roles("USER")
                .build();

        UserDetails admin = User.withUsername("admin")
                .password(passwordEncoder.encode("1234"))
                .roles("ADMIN", "USER")
                .build();

        UserDetails invite = User.withUsername("invite")
                .password(passwordEncoder.encode("0000"))
                .roles("INVITE")
                .build();

        return new InMemoryUserDetailsManager(user, admin, invite);
    }

    /**
     * Chaine de filtres de securite.
     *
     * @param http    constructeur fourni par Spring Security
     * @param journal journal alimente sur succes et echec
     * @return la chaine configuree
     * @throws Exception si la configuration echoue
     */
    @Bean
    public SecurityFilterChain securityFilterChain(HttpSecurity http) throws Exception {
        http
                .authorizeHttpRequests(auth -> auth
                        .requestMatchers("/", "/css/**", "/login", "/acces-refuse").permitAll()
                        .requestMatchers("/user/**").hasRole("USER")
                        .requestMatchers("/admin/**").hasRole("ADMIN")
                        .anyRequest().authenticated()
                )
                .formLogin(form -> form
                        .loginPage("/login")
                        .successHandler(redirectionSelonRole())
                        .failureUrl("/login?error")
                        .permitAll()
                )
                .logout(logout -> logout
                        .logoutUrl("/logout")
                        .logoutSuccessUrl("/login?logout")
                        .invalidateHttpSession(true)
                        .deleteCookies("JSESSIONID")
                        .permitAll()
                )
                .exceptionHandling(gestion -> gestion
                        .accessDeniedPage("/acces-refuse")
                );
        return http.build();
    }

    /**
     * Redirige vers l'espace correspondant au role apres une connexion reussie.
     *
     * @return le gestionnaire de succes
     */
    private AuthenticationSuccessHandler redirectionSelonRole() {
        return (requete, reponse, authentification) -> {
            boolean administrateur = authentification.getAuthorities().stream()
                    .anyMatch(autorite -> autorite.getAuthority().equals("ROLE_ADMIN"));
            reponse.sendRedirect(administrateur ? "/admin/dashboard" : "/user/dashboard");
        };
    }
}
