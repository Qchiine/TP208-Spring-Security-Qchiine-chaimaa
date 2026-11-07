package ma.fstg.security.web;

import ma.fstg.security.audit.JournalConnexions;
import org.springframework.security.core.Authentication;
import org.springframework.stereotype.Controller;
import org.springframework.ui.Model;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestParam;

/**
 * Controleur des pages de l'application.
 * <p>
 * Trois zones : accueil public, espace utilisateur et espace administrateur.
 * Le journal des connexions est expose sur une page consultee uniquement par
 * l'administrateur, ce qui illustre le controle d'acces par role.
 */
@Controller
public class HomeController {

    private final JournalConnexions journal;

    /**
     * @param journal journal partage des tentatives de connexion
     */
    public HomeController(JournalConnexions journal) {
        this.journal = journal;
    }

    /**
     * @return la vue d'accueil publique
     */
    @GetMapping("/")
    public String index() {
        return "index";
    }

    /**
     * Espace reserve au role USER.
     *
     * @param authentication utilisateur connecte
     * @param model          modele de la vue
     * @return la vue du tableau de bord utilisateur
     */
    @GetMapping("/user/dashboard")
    public String userDashboard(Authentication authentication, Model model) {
        model.addAttribute("utilisateur", authentication.getName());
        model.addAttribute("roles", authentication.getAuthorities());
        model.addAttribute("derniereConnexion", journal.derniereReussie(authentication.getName()));
        return "user_dashboard";
    }

    /**
     * Espace reserve au role ADMIN.
     *
     * @param authentication utilisateur connecte
     * @param model          modele de la vue
     * @return la vue du tableau de bord administrateur
     */
    @GetMapping("/admin/dashboard")
    public String adminDashboard(Authentication authentication, Model model) {
        model.addAttribute("utilisateur", authentication.getName());
        model.addAttribute("roles", authentication.getAuthorities());
        model.addAttribute("tentatives", journal.total());
        model.addAttribute("echecs", journal.echecs());
        return "admin_dashboard";
    }

    /**
     * Journal detaille des connexions, reserve a l'administrateur.
     *
     * @param model modele de la vue
     * @return la vue du journal
     */
    @GetMapping("/admin/journal")
    public String journal(Model model) {
        model.addAttribute("entrees", journal.entrees());
        model.addAttribute("total", journal.total());
        model.addAttribute("echecs", journal.echecs());
        return "journal";
    }

    /**
     * Formulaire de connexion personnalise.
     *
     * @param erreur present lorsque l'authentification a echoue
     * @param sortie present lorsque l'utilisateur vient de se deconnecter
     * @param model  modele de la vue
     * @return la vue de connexion
     */
    @GetMapping("/login")
    public String login(
            @RequestParam(name = "error", required = false) String erreur,
            @RequestParam(name = "logout", required = false) String sortie,
            Model model) {
        model.addAttribute("erreur", erreur != null);
        model.addAttribute("sortie", sortie != null);
        return "login";
    }

    /**
     * Page affichee apres un refus d'acces.
     *
     * @return la vue d'erreur 403
     */
    @GetMapping("/acces-refuse")
    public String accesRefuse() {
        return "acces_refuse";
    }
}
