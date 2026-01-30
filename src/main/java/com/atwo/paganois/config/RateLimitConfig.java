package com.atwo.paganois.config;

import org.springframework.boot.context.properties.ConfigurationProperties;

/**
 * Configuração de Rate Limiting
 * 
 * Valores podem ser sobrescritos no application.properties: rate-limit.login.capacity=5
 * rate-limit.login.refill-tokens=5 rate-limit.login.refill-minutes=1
 */
@ConfigurationProperties(prefix = "rate-limit")
public class RateLimitConfig {

    private EndpointLimit login = new EndpointLimit(5, 5, 1);
    private EndpointLimit register = new EndpointLimit(3, 3, 60);
    private EndpointLimit forgotPassword = new EndpointLimit(3, 3, 60);
    private EndpointLimit resendVerification = new EndpointLimit(3, 3, 60);
    private EndpointLimit general = new EndpointLimit(100, 100, 1);

    // Cache settings
    private int cacheMaxSize = 10000;
    private int cacheExpireMinutes = 60;

    public static class EndpointLimit {
        private int capacity;
        private int refillTokens;
        private int refillMinutes;

        public EndpointLimit() {}

        public EndpointLimit(int capacity, int refillTokens, int refillMinutes) {
            this.capacity = capacity;
            this.refillTokens = refillTokens;
            this.refillMinutes = refillMinutes;
        }

        public int getCapacity() {
            return capacity;
        }

        public void setCapacity(int capacity) {
            this.capacity = capacity;
        }

        public int getRefillTokens() {
            return refillTokens;
        }

        public void setRefillTokens(int refillTokens) {
            this.refillTokens = refillTokens;
        }

        public int getRefillMinutes() {
            return refillMinutes;
        }

        public void setRefillMinutes(int refillMinutes) {
            this.refillMinutes = refillMinutes;
        }
    }

    // Getters e Setters

    public EndpointLimit getLogin() {
        return login;
    }

    public void setLogin(EndpointLimit login) {
        this.login = login;
    }

    public EndpointLimit getRegister() {
        return register;
    }

    public void setRegister(EndpointLimit register) {
        this.register = register;
    }

    public EndpointLimit getForgotPassword() {
        return forgotPassword;
    }

    public void setForgotPassword(EndpointLimit forgotPassword) {
        this.forgotPassword = forgotPassword;
    }

    public EndpointLimit getResendVerification() {
        return resendVerification;
    }

    public void setResendVerification(EndpointLimit resendVerification) {
        this.resendVerification = resendVerification;
    }

    public EndpointLimit getGeneral() {
        return general;
    }

    public void setGeneral(EndpointLimit general) {
        this.general = general;
    }

    public int getCacheMaxSize() {
        return cacheMaxSize;
    }

    public void setCacheMaxSize(int cacheMaxSize) {
        this.cacheMaxSize = cacheMaxSize;
    }

    public int getCacheExpireMinutes() {
        return cacheExpireMinutes;
    }

    public void setCacheExpireMinutes(int cacheExpireMinutes) {
        this.cacheExpireMinutes = cacheExpireMinutes;
    }
}
