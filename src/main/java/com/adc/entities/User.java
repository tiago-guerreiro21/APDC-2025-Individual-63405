package com.adc.entities;

import com.google.cloud.datastore.Entity;

public class User {
    private String email;
    private String username;
    private String fullName;
    private String phone;
    private String password;
    private String profile; // "público" ou "privado"
    private String role; // ENDUSER, BACKOFFICE, ADMIN, PARTNER
    private String accountState; // ATIVADA, DESATIVADA, SUSPENSA

    // Atributos opcionais 
    private String citizenCardNumber;
    private String nif;
    private String employer;
    private String jobTitle;
    private String address;
    private String employerNif;

    public User() {}
    
    public User(Entity entity) {
        this.email = entity.getString("email");
        this.username = entity.getString("username");
        this.fullName = entity.getString("fullName");
        this.phone = entity.getString("phone");
        this.password = entity.getString("password");
        this.profile = entity.getString("profile");
        this.role = entity.getString("role");
        this.accountState = entity.getString("accountState");
        
        this.citizenCardNumber = entity.contains("citizenCardNumber") ? entity.getString("citizenCardNumber") : null;
        this.nif = entity.contains("nif") ? entity.getString("nif") : null;
        this.employer = entity.contains("employer") ? entity.getString("employer") : null;
        this.jobTitle = entity.contains("jobTitle") ? entity.getString("jobTitle") : null;
        this.address = entity.contains("address") ? entity.getString("address") : null;
        this.employerNif = entity.contains("employerNif") ? entity.getString("employerNif") : null;
    }

    public String getEmail() {
        return email;
    }

    public void setEmail(String email) {
        this.email = email;
    }

    public String getUsername() {
        return username;
    }

    public void setUsername(String username) {
        this.username = username;
    }

    public String getFullName() {
        return fullName;
    }

    public void setFullName(String fullName) {
        this.fullName = fullName;
    }

    public String getPhone() {
        return phone;
    }

    public void setPhone(String phone) {
        this.phone = phone;
    }

    public String getPassword() {
        return password;
    }

    public void setPassword(String password) {
        this.password = password;
    }

    public String getProfile() {
        return profile;
    }

    public void setProfile(String profile) {
        this.profile = profile;
    }

    public String getRole() {
        return role;
    }

    public void setRole(String role) {
        this.role = role;
    }

    public String getAccountState() {
        return accountState;
    }

    public void setAccountState(String accountState) {
        this.accountState = accountState;
    }

    public String getCitizenCardNumber() {
        return citizenCardNumber;
    }

    public void setCitizenCardNumber(String citizenCardNumber) {
        this.citizenCardNumber = citizenCardNumber;
    }

    public String getNif() {
        return nif;
    }

    public void setNif(String nif) {
        this.nif = nif;
    }

    public String getEmployer() {
        return employer;
    }

    public void setEmployer(String employer) {
        this.employer = employer;
    }

    public String getJobTitle() {
        return jobTitle;
    }

    public void setJobTitle(String jobTitle) {
        this.jobTitle = jobTitle;
    }

    public String getAddress() {
        return address;
    }

    public void setAddress(String address) {
        this.address = address;
    }

    public String getEmployerNif() {
        return employerNif;
    }

    public void setEmployerNif(String employerNif) {
        this.employerNif = employerNif;
    }
}