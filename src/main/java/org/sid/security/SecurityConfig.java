package org.sid.security;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.config.annotation.authentication.builders.AuthenticationManagerBuilder;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configuration.WebSecurityConfigurerAdapter;
import org.springframework.security.config.http.SessionCreationPolicy;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.web.authentication.UsernamePasswordAuthenticationFilter;

@Configuration
@EnableWebSecurity
public class SecurityConfig extends WebSecurityConfigurerAdapter {

    @Autowired
    private UserDetailsService userDetailsService;//on injecte la classe UserDetailsService
    @Autowired
    private BCryptPasswordEncoder bCryptPasswordEncoder; //on injecte la classe BCryptPasswordEncoder

    @Override //configuration de l'authentification avec un objet AuthenticationManagerBuilder
    protected void configure(AuthenticationManagerBuilder auth) throws Exception {
        auth.userDetailsService(userDetailsService).passwordEncoder(bCryptPasswordEncoder);
    }

    @Override//configuration de l'acces http
    protected void configure(HttpSecurity http) throws Exception {
        //http.formLogin();//utilisation de formulaire pour s'authentifier avec la configuration par default

        /**
         * Desactivatron des sessions
         */
        http.csrf().disable();//On desactive la generation  de csrf token
        http.sessionManagement().sessionCreationPolicy(SessionCreationPolicy.STATELESS);//Non usage des Session

        /**
         * Gestion des acces
         */
        //Authoriser à tout le monde d'acceder à la page d'authentification et aussi de pouvoir s'enregister comme nouveau utilisateur
        http.authorizeRequests().antMatchers("/login/**","/register/**").permitAll();
        //Authoriser à être admin pour la gestion des Users et des Roles
        http.authorizeRequests().antMatchers("/appUsers/**","/appRoles/**").hasAuthority("ADMIN");
        //Obliger à s'authentifier pour toute autre requete
        http.authorizeRequests().anyRequest().authenticated();


        /**
         * Gerer les filtre
         */
        http.addFilter(new JWTAuthenticationFilter(authenticationManager()));
        http.addFilterBefore(new JWTAuthoriazationFilter(), UsernamePasswordAuthenticationFilter.class);
    }
}
