package org.sid.security;

import com.auth0.jwt.JWT;
import com.auth0.jwt.algorithms.Algorithm;
import com.fasterxml.jackson.databind.ObjectMapper;
import org.sid.entities.AppUser;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.config.annotation.authentication.builders.AuthenticationManagerBuilder;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.core.userdetails.User;
import org.springframework.security.web.authentication.UsernamePasswordAuthenticationFilter;

import javax.servlet.FilterChain;
import javax.servlet.ServletException;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.io.IOException;
import java.util.ArrayList;
import java.util.Date;
import java.util.List;

public class JWTAuthenticationFilter extends UsernamePasswordAuthenticationFilter {
    private AuthenticationManager authenticationManager;

    public JWTAuthenticationFilter(AuthenticationManager authenticationManager) {
        this.authenticationManager = authenticationManager;
    }

    @Override //recuperation des informations d'authentification via un formulaire par exemple
    public Authentication attemptAuthentication(HttpServletRequest request, HttpServletResponse response) throws AuthenticationException {

        try {
            //recuperation des infos que l'utilisateur a saisi (par exemple: username et password)
           AppUser appUser = new ObjectMapper().readValue(request.getInputStream(),AppUser.class);
           return authenticationManager.authenticate(new UsernamePasswordAuthenticationToken(appUser.getUsername(), appUser.getPassword()));
        } catch (IOException e) {
            e.printStackTrace();
            throw new RuntimeException(e);
        }
    }

    @Override
    protected void successfulAuthentication(HttpServletRequest request, HttpServletResponse response,
                                            FilterChain chain, Authentication authResult) throws IOException, ServletException {

        //recuperation de l'utilisateur authentifier
        User user = (User) authResult.getPrincipal();

        //recuperation des roles de l'utilisateur authentifier
        List<String> roles = new ArrayList<>();
        authResult.getAuthorities().forEach(a->{
            roles.add(a.getAuthority());
        });

        String jwt = JWT.create()
                .withIssuer(request.getRequestURI()) //Recuperer Uri de la requete
                .withSubject(user.getUsername()) //Recuperer le username
                .withArrayClaim("roles",roles.toArray(new String[roles.size()])) //Recuperer les roles
                .withExpiresAt(new Date(System.currentTimeMillis() + SecurityParams.EXPIRATION)) //Definir la duree de vie du token
                .sign(Algorithm.HMAC256(SecurityParams.SECRET)); //La clés secrete pour crypter le token

        //on renvoie la reponse avec comme SecurityParams.JWT_HEADER_NAME et le token jwt créé
        response.addHeader(SecurityParams.JWT_HEADER_NAME,jwt);
    }
}
