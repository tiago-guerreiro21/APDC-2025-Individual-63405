package com.adc.entities;

import com.google.cloud.datastore.Entity;
import com.google.cloud.datastore.Key;

public class User {
    // Atributos 
    private String email;
    private String username;
    private String fullName;
    private String phone;
    private String password;
    private String profile; // "público" ou "privado"
    private String role = "enduser"; // ENDUSER, BACKOFFICE, ADMIN
    private String accountState = "DESATIVADA"; // ATIVADA, DESATIVADA, SUSPENSA

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

}