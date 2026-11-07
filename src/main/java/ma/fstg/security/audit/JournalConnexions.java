package ma.fstg.security.audit;

import org.springframework.context.event.EventListener;
import org.springframework.security.authentication.event.AbstractAuthenticationFailureEvent;
import org.springframework.security.authentication.event.AuthenticationSuccessEvent;
import org.springframework.security.core.Authentication;
import org.springframework.stereotype.Component;

import java.time.LocalDateTime;
import java.time.format.DateTimeFormatter;
import java.util.ArrayList;
import java.util.Collections;
import java.util.List;
import java.util.Optional;

/**
 * Journal des tentatives de connexion.
 * <p>
 * Spring Security publie un evenement a chaque succes et a chaque echec
 * d'authentification. Ce composant les ecoute et conserve une trace horodatee
 * en memoire : c'est la brique d'observabilite qui manque a une application
 * securisee classique, ou l'on ne sait jamais qui a tente de se connecter.
 */
@Component
public class JournalConnexions {

    private static final DateTimeFormatter FORMAT =
            DateTimeFormatter.ofPattern("dd/MM/yyyy HH:mm:ss");

    private static final int CAPACITE = 50;

    private final List<Entree> entrees = Collections.synchronizedList(new ArrayList<>());
    private int echecs;
    private int succes;

    /**
     * Ligne du journal.
     *
     * @param utilisateur nom saisi
     * @param moment      horodatage
     * @param reussie     vrai si l'authentification a abouti
     * @param motif       message d'erreur, vide en cas de succes
     */
    public record Entree(String utilisateur, String moment, boolean reussie, String motif) {

        /** @return le sens de la tentative, pret a afficher */
        public String issue() {
            return reussie ? "succes" : "echec";
        }
    }

    /**
     * Enregistre un succes d'authentification.
     *
     * @param evenement evenement publie par Spring Security
     */
    @EventListener
    public void surSucces(AuthenticationSuccessEvent evenement) {
        Authentication authentification = evenement.getAuthentication();
        succes++;
        ajouter(new Entree(authentification.getName(),
                LocalDateTime.now().format(FORMAT), true, ""));
    }

    /**
     * Enregistre un echec d'authentification.
     *
     * @param evenement evenement publie par Spring Security
     */
    @EventListener
    public void surEchec(AbstractAuthenticationFailureEvent evenement) {
        echecs++;
        String utilisateur = String.valueOf(evenement.getAuthentication().getName());
        String motif = evenement.getException().getMessage();
        ajouter(new Entree(utilisateur, LocalDateTime.now().format(FORMAT), false, motif));
    }

    private void ajouter(Entree entree) {
        entrees.add(0, entree);
        while (entrees.size() > CAPACITE) {
            entrees.remove(entrees.size() - 1);
        }
    }

    /**
     * @return les entrees, de la plus recente a la plus ancienne
     */
    public List<Entree> entrees() {
        synchronized (entrees) {
            return List.copyOf(entrees);
        }
    }

    /** @return le nombre total de tentatives */
    public int total() {
        return succes + echecs;
    }

    /** @return le nombre d'echecs */
    public int echecs() {
        return echecs;
    }

    /** @return le nombre de succes */
    public int succes() {
        return succes;
    }

    /**
     * Derniere connexion reussie d'un utilisateur.
     *
     * @param utilisateur nom de l'utilisateur
     * @return l'horodatage, ou un Optional vide
     */
    public Optional<String> derniereReussie(String utilisateur) {
        synchronized (entrees) {
            return entrees.stream()
                    .filter(Entree::reussie)
                    .filter(entree -> entree.utilisateur().equals(utilisateur))
                    .map(Entree::moment)
                    .findFirst();
        }
    }

    /** Vide le journal, utile pour les tests. */
    public void reinitialiser() {
        entrees.clear();
        succes = 0;
        echecs = 0;
    }
}
