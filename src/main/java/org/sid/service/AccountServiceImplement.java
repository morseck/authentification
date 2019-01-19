package org.sid.service;

//import org.sid.dao.AppRoleRepository1;
import org.sid.dao.AppRoleRepository;
import org.sid.dao.AppUserRepository;
import org.sid.entities.AppRole;
import org.sid.entities.AppUser;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.stereotype.Service;

import javax.transaction.Transactional;

@Service
@Transactional
public class AccountServiceImplement implements AccountService {

    private AppUserRepository appUserRepository;
    private AppRoleRepository appRoleRepository;
    private BCryptPasswordEncoder bCryptPasswordEncoder;

    public AccountServiceImplement(AppUserRepository appUserRepository, AppRoleRepository appRoleRepository, BCryptPasswordEncoder bCryptPasswordEncoder) {
        this.appUserRepository = appUserRepository;
        this.appRoleRepository = appRoleRepository;
        this.bCryptPasswordEncoder = bCryptPasswordEncoder;
    }


    @Override
    public AppUser saveUser(String username, String password, String confirmedPassword) {

        //on recupere le user qui comme nom d'utilisateur username
        AppUser user = appUserRepository.findByUsername(username);

        //si le user existe deja
        if (user!=null) throw new RuntimeException("User already exist");

        //si le mot de passe n'est pas le même
        if (!password.equals(confirmedPassword)) throw new RuntimeException("Please confirm your password");

        AppUser appUser = new AppUser();
        appUser.setUsername(username);
        appUser.setActived(true);//activer l'utilisateur par default
        appUser.setPassword(bCryptPasswordEncoder.encode(password));//crypter le mot de passe avant de l'enregistrer
        appUserRepository.save(appUser);//on enregistre le user dans la base de donnees

        addRoleToUser(username,"USER"); //on ajoute par default un role USER à l'utilisateur

        return appUser;
    }

    @Override
    public AppRole save(AppRole role) {
        return appRoleRepository.save(role);

    }

    @Override
    public AppUser loadUserByUsername(String username) {
        return appUserRepository.findByUsername(username);

    }

    @Override
    public void addRoleToUser(String username, String roleName) {
        AppUser appUser = appUserRepository.findByUsername(username);//recuperer le role
        AppRole appRole = appRoleRepository.findByNameRole(roleName);//recuperer le role

        appUser.getRoles().add(appRole);//assigner un role à l'utilisateur
    }
}
