package org.sid.security;

/**
 * Definition des constantes que nous allons utiliser dans le microservice
 */
public interface SecurityParams {
    public static final String JWT_HEADER_NAME = "Authorization"; //l'entête du token jwt créée
    public static final String SECRET = "genietech@gmail.com"; // notre clés secret pour crypter les informations qui sont dans le token jwt
    public static final long EXPIRATION = 10*24*3600*1000; //Durée de vie du token jwt : 10jours ==> unite miliseconde et non seconde ==> *1000
    public static final String HEADER_PREFIX = "Bearer "; //prefix du token jwt créé
}
