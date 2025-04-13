package com.adc.util;

import java.util.UUID;

public class AuthToken {
    public static final long EXPIRATION_TIME = 1000 * 60 * 60 * 2; // 2 horas
    
    // Estrutura completa conforme enunciado
    public final String tokenID;
    public final String USER;       // username
    public final String ROLE;       // papel do utilizador
    public final Validity VALIDITY; // período de validade
    public final String VERIFIER; // número mágico/aleatório

    public static class Validity {
        public final long VALID_FROM; // data de emissão
        public final long VALID_TO;   // data de expiração

        public Validity(long validFrom, long validTo) {
            this.VALID_FROM = validFrom;
            this.VALID_TO = validTo;
        }
    }

    public AuthToken(String username, String role) {
        this.tokenID = UUID.randomUUID().toString();
        this.USER = username;
        this.ROLE = role;
        long currentTime = System.currentTimeMillis();
        this.VALIDITY = new Validity(currentTime, currentTime + EXPIRATION_TIME);
        this.VERIFIER = UUID.randomUUID().toString().replace("-", "").substring(0, 16);
    }

    // Getters (opcionais, mas recomendados)
    public String getTokenID() { return tokenID; }
    public String getUSER() { return USER; }
    public String getROLE() { return ROLE; }
    public Validity getVALIDITY() { return VALIDITY; }
    public String getVERIFICADOR() { return VERIFIER; }
}