package ma.fstg.security;

import ma.fstg.security.audit.JournalConnexions;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.autoconfigure.web.servlet.AutoConfigureMockMvc;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.test.web.servlet.MockMvc;

import static org.junit.jupiter.api.Assertions.assertNotEquals;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.springframework.security.test.web.servlet.request.SecurityMockMvcRequestBuilders.formLogin;
import static org.springframework.security.test.web.servlet.request.SecurityMockMvcRequestPostProcessors.csrf;
import static org.springframework.security.test.web.servlet.request.SecurityMockMvcRequestPostProcessors.user;
import static org.springframework.security.test.web.servlet.response.SecurityMockMvcResultMatchers.authenticated;
import static org.springframework.security.test.web.servlet.response.SecurityMockMvcResultMatchers.unauthenticated;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.post;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.content;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.redirectedUrl;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.redirectedUrlPattern;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.view;

/**
 * Verifie les regles d'acces, l'authentification et la deconnexion.
 * <p>
 * Les tests utilisent MockMvc et les utilitaires de spring-security-test :
 * aucune requete reelle n'est emise, mais toute la chaine de filtres est
 * traversee.
 */
@SpringBootTest
@AutoConfigureMockMvc
@DisplayName("Securite de l'application")
class SecurityTest {

    @Autowired
    private MockMvc mockMvc;

    @Autowired
    private PasswordEncoder passwordEncoder;

    @Autowired
    private JournalConnexions journal;

    @BeforeEach
    void preparer() {
        journal.reinitialiser();
    }

    @Test
    @DisplayName("la page d'accueil est publique")
    void accueilPublic() throws Exception {
        mockMvc.perform(get("/"))
                .andExpect(status().isOk())
                .andExpect(view().name("index"));
    }

    @Test
    @DisplayName("une zone protegee redirige un visiteur vers la connexion")
    void zoneProtegeeRedirige() throws Exception {
        mockMvc.perform(get("/user/dashboard"))
                .andExpect(status().is3xxRedirection())
                .andExpect(redirectedUrlPattern("**/login"));
    }

    @Test
    @DisplayName("le formulaire de connexion est accessible sans authentification")
    void formulaireAccessible() throws Exception {
        mockMvc.perform(get("/login"))
                .andExpect(status().isOk())
                .andExpect(view().name("login"))
                .andExpect(content().string(org.hamcrest.Matchers.containsString("Veuillez vous identifier")));
    }

    @Test
    @DisplayName("le compte user accede a son espace")
    void userAccedeSonEspace() throws Exception {
        mockMvc.perform(get("/user/dashboard").with(user("user").roles("USER")))
                .andExpect(status().isOk())
                .andExpect(view().name("user_dashboard"));
    }

    @Test
    @DisplayName("le compte user est refuse sur l'espace administrateur")
    void userRefuseSurAdmin() throws Exception {
        mockMvc.perform(get("/admin/dashboard").with(user("user").roles("USER")))
                .andExpect(status().isForbidden());
    }

    @Test
    @DisplayName("le compte admin accede aux deux espaces")
    void adminAccedeAuxDeuxEspaces() throws Exception {
        mockMvc.perform(get("/user/dashboard").with(user("admin").roles("ADMIN", "USER")))
                .andExpect(status().isOk());

        mockMvc.perform(get("/admin/dashboard").with(user("admin").roles("ADMIN", "USER")))
                .andExpect(status().isOk())
                .andExpect(view().name("admin_dashboard"));
    }

    @Test
    @DisplayName("un compte sans role est refuse sur les deux espaces")
    void compteSansRoleRefuse() throws Exception {
        mockMvc.perform(get("/user/dashboard").with(user("invite").roles("INVITE")))
                .andExpect(status().isForbidden());

        mockMvc.perform(get("/admin/dashboard").with(user("invite").roles("INVITE")))
                .andExpect(status().isForbidden());
    }

    @Test
    @DisplayName("l'authentification avec un bon mot de passe aboutit")
    void authentificationReussie() throws Exception {
        mockMvc.perform(formLogin("/login").user("user").password("1111"))
                .andExpect(authenticated().withUsername("user"));
    }

    @Test
    @DisplayName("l'authentification avec un mauvais mot de passe echoue")
    void authentificationEchouee() throws Exception {
        mockMvc.perform(formLogin("/login").user("user").password("mauvais"))
                .andExpect(unauthenticated())
                .andExpect(redirectedUrl("/login?error"));
    }

    @Test
    @DisplayName("un compte inconnu est refuse")
    void compteInconnu() throws Exception {
        mockMvc.perform(formLogin("/login").user("fantome").password("1111"))
                .andExpect(unauthenticated());
    }

    @Test
    @DisplayName("le role ADMIN redirige vers l'espace administrateur")
    void redirectionAdmin() throws Exception {
        mockMvc.perform(post("/login")
                        .param("username", "admin")
                        .param("password", "1234")
                        .with(csrf()))
                .andExpect(status().is3xxRedirection())
                .andExpect(redirectedUrl("/admin/dashboard"));
    }

    @Test
    @DisplayName("le role USER redirige vers son espace")
    void redirectionUser() throws Exception {
        mockMvc.perform(post("/login")
                        .param("username", "user")
                        .param("password", "1111")
                        .with(csrf()))
                .andExpect(status().is3xxRedirection())
                .andExpect(redirectedUrl("/user/dashboard"));
    }

    @Test
    @DisplayName("la deconnexion renvoie vers la connexion avec le marqueur")
    void deconnexion() throws Exception {
        mockMvc.perform(post("/logout")
                        .with(user("user").roles("USER"))
                        .with(csrf()))
                .andExpect(status().is3xxRedirection())
                .andExpect(redirectedUrl("/login?logout"));
    }

    @Test
    @DisplayName("les mots de passe sont haches avec BCrypt")
    void motsDePasseHaches() {
        String hache = passwordEncoder.encode("1111");

        assertNotEquals("1111", hache);
        assertTrue(hache.startsWith("$2a$") || hache.startsWith("$2b$"),
                "un hash BCrypt commence par $2a$ ou $2b$ : " + hache);
        assertTrue(passwordEncoder.matches("1111", hache));
    }

    @Test
    @DisplayName("deux hachages du meme mot de passe sont differents")
    void selAleatoire() {
        String premier = passwordEncoder.encode("1111");
        String second = passwordEncoder.encode("1111");

        assertNotEquals(premier, second, "BCrypt utilise un sel aleatoire");
        assertTrue(passwordEncoder.matches("1111", premier));
        assertTrue(passwordEncoder.matches("1111", second));
    }

    @Test
    @DisplayName("le journal enregistre les connexions reussies")
    void journalEnregistreSucces() throws Exception {
        mockMvc.perform(formLogin("/login").user("user").password("1111"))
                .andExpect(authenticated());

        assertTrue(journal.total() >= 1);
        assertTrue(journal.succes() >= 1);
        assertTrue(journal.derniereReussie("user").isPresent());
    }

    @Test
    @DisplayName("le journal enregistre les echecs")
    void journalEnregistreEchecs() throws Exception {
        mockMvc.perform(formLogin("/login").user("user").password("faux"))
                .andExpect(unauthenticated());

        assertTrue(journal.echecs() >= 1);
    }

    @Test
    @DisplayName("le journal est reserve a l'administrateur")
    void journalReserveAdmin() throws Exception {
        mockMvc.perform(get("/admin/journal").with(user("user").roles("USER")))
                .andExpect(status().isForbidden());

        mockMvc.perform(get("/admin/journal").with(user("admin").roles("ADMIN", "USER")))
                .andExpect(status().isOk())
                .andExpect(view().name("journal"));
    }

    @Test
    @DisplayName("la page d'acces refuse est publique")
    void pageRefusAccessible() throws Exception {
        mockMvc.perform(get("/acces-refuse"))
                .andExpect(status().isOk())
                .andExpect(view().name("acces_refuse"));
    }

    @Test
    @DisplayName("la feuille de style est servie sans authentification")
    void feuilleDeStylePublique() throws Exception {
        mockMvc.perform(get("/css/style.css"))
                .andExpect(status().isOk());
    }
}
