package org.sid.security;

import com.auth0.jwt.JWT;
import com.auth0.jwt.JWTVerifier;
import com.auth0.jwt.algorithms.Algorithm;
import com.auth0.jwt.interfaces.DecodedJWT;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.web.filter.OncePerRequestFilter;

import javax.servlet.FilterChain;
import javax.servlet.ServletException;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.io.IOException;
import java.util.ArrayList;
import java.util.Collection;
import java.util.List;

public class JWTAuthoriazationFilter extends OncePerRequestFilter {

    @Override //pour chaque requete de l'utilisateur cette methode s'execute d'abord
    protected void doFilterInternal(HttpServletRequest request, HttpServletResponse response,
                                    FilterChain filterChain) throws ServletException, IOException {

        //On authorise à tous les domaines de nous envoyer des requete
        response.addHeader("Access-Control-Allow-Origin","*");
        //On authorise aux navigateurs de nous envoyer seulement ces entêtes "Origin,Accept,X-Requested-With,Content-Type,Access-Control-Request-Method,Access-Control-Request-Headers,authorization"
        response.addHeader("Access-Control-Allow-Headers","Origin,Accept,X-Requested-With,Content-Type,Access-Control-Request-Method,Access-Control-Request-Headers,authorization");
        response.addHeader("Access-Control-Expose-Headers","Access-Control-Allow-Origin,Access-Control-Allow-Credentials,authorization");
        //Permettre aux methods "GET","POST","PUT", "DELETE","CREATE" de Core de pouvoir les utiliser
        response.addHeader("Access-Control-Allow-Method", "GET,POST,PUT,DELETE,PATCH");

        if (request.getRequestURI().equals("OPTIONS")){
            response.setStatus(HttpServletResponse.SC_OK);
        }
        //Pas besoin de regarder le token quand un User veut s'authentifier
        else if (request.getRequestURI().equals("/login")){
            filterChain.doFilter(request,response);
            return;
        }
        else {
            String jwtToken = request.getHeader(SecurityParams.JWT_HEADER_NAME); //Recupearation du jwt
            System.out.println("TOKEN=" + jwtToken);
            //Verification si l'utilisateur est auhtoriser
            if (jwtToken == null || !jwtToken.startsWith(SecurityParams.HEADER_PREFIX)) {
                filterChain.doFilter(request, response);// Passage au filtre suivant qui va rejeter l'acces
                return;
            }
            //Creation de l'objet JWTVerifier avec la même clés secrete du token pour la verification
            JWTVerifier verifier = JWT.require(Algorithm.HMAC256(SecurityParams.SECRET)).build();

            //Recuperation du token jwt décodé sans le prefix representé ici par SecurityParams.HEADER_PREFIX
            String jwt = jwtToken.substring(SecurityParams.HEADER_PREFIX.length());
            DecodedJWT decodedJWT = verifier.verify(jwt);

            System.out.println("JWT=" + jwt);

            //Recuperation du username du token decodé decodedJWT
            String username = decodedJWT.getSubject();
            //Recuperation des roles du token décodé decodedJWT
            List<String> roles = decodedJWT.getClaims().get("roles").asList(String.class);

            System.out.println("username=" + username);
            System.out.println("roles" + roles);

            Collection<GrantedAuthority> authorities = new ArrayList<>();
            roles.forEach(rn -> {
                authorities.add(new SimpleGrantedAuthority(rn));
            });

            /**
             * Ordonner à Spring de
             * Authentifier le user porté par le JWT
             *
             */
            //Creation d'un objet user de spring security
            UsernamePasswordAuthenticationToken user = new UsernamePasswordAuthenticationToken(username, null, authorities);
            //Authentification du user
            SecurityContextHolder.getContext().setAuthentication(user);
            filterChain.doFilter(request, response);

        }//fin else
    }
}
