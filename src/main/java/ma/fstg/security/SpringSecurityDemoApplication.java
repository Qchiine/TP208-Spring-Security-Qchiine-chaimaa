package ma.fstg.security;

import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;

/**
 * Point d'entree de l'application securisee.
 * <p>
 * Sans configuration supplementaire, Spring Security protegerait toutes les
 * routes et genererait un utilisateur unique dont le mot de passe aleatoire
 * apparait dans la console : c'est le comportement par defaut etudie a l'etape 2.
 */
@SpringBootApplication
public class SpringSecurityDemoApplication {

    /**
     * @param args arguments de la ligne de commande
     */
    public static void main(String[] args) {
        SpringApplication.run(SpringSecurityDemoApplication.class, args);
    }
}
