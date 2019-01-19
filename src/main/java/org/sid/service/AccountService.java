package org.sid.service;

//import org.sid.entities.AppRole;
import org.sid.entities.AppRole;
import org.sid.entities.AppUser;

public interface AccountService {
    public AppUser saveUser(String username, String password, String confirmedPassword);//permet de sauvegarder un utilisateur
    public AppRole save(AppRole role);//permet d'ennregistrer un role avec un nom de role
    public AppUser loadUserByUsername(String username);//permet de charger un utilisateur apartir de son username
    public void addRoleToUser(String username, String roleName);//permet d'ajouter un role à un utilisateu
}
