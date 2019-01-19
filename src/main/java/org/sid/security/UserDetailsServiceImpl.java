package org.sid.security;

import org.sid.entities.AppUser;
import org.sid.service.AccountService;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.userdetails.User;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.stereotype.Service;

import java.util.ArrayList;
import java.util.Collection;

@Service
public class UserDetailsServiceImpl implements UserDetailsService {

    @Autowired
    private AccountService accountService;//injection de la classe AccountService

    @Override
    public UserDetails loadUserByUsername(String username) throws UsernameNotFoundException {
        AppUser appUser = accountService.loadUserByUsername(username);

        //verification si le user exit
        if (appUser == null) throw new  UsernameNotFoundException("invalid user");
        //creation d'une collection de GrantAuthority dans laquelle on va  ajouter les role de l'utilisateur
        Collection<GrantedAuthority> authorities = new ArrayList<>();
        appUser.getRoles().forEach(r->{
           authorities.add(new SimpleGrantedAuthority(r.getNameRole()));
        });

        //on retourne dans un objet User de UserDetails : le username, le password et les role
        return new User(appUser.getUsername(),appUser.getPassword(), authorities);
    }
}
