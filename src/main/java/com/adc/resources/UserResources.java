package com.adc.resources;

import java.util.Arrays;
import java.util.List;
import java.util.logging.Logger;

import org.apache.commons.codec.digest.DigestUtils;

import com.adc.entities.User;
import com.google.cloud.datastore.*;
import com.google.cloud.datastore.DatastoreOptions;
import jakarta.annotation.PostConstruct;
import jakarta.ws.rs.*;
import jakarta.ws.rs.core.MediaType;
import jakarta.ws.rs.core.Response;
import jakarta.ws.rs.core.Response.Status;

@Path("/users")
public class UserResources {
    // Constantes para roles
    private static final String ROLE_ENDUSER = "ENDUSER";
    private static final String ROLE_BACKOFFICE = "BACKOFFICE";
    private static final String ROLE_ADMIN = "ADMIN";
    private static final String ROLE_PARTNER = "PARTNER";
    
    // Constantes para estados da conta
    private static final String ACCOUNT_STATE_ACTIVATED = "ATIVADA";
    private static final String ACCOUNT_STATE_DEACTIVATED = "DESATIVADA";
    private static final String ACCOUNT_STATE_SUSPENDED = "SUSPENSA";
    
    // Constantes para propriedades
    private static final String PROP_USERNAME = "username";
    private static final String PROP_EMAIL = "email";
    private static final String PROP_FULLNAME = "fullName";
    private static final String PROP_PHONE = "phone";
    private static final String PROP_PASSWORD = "password";
    private static final String PROP_PROFILE = "profile";
    private static final String PROP_ROLE = "role";
    private static final String PROP_ACCOUNT_STATE = "accountState";
    private static final String PROP_TOKEN_ID = "tokenID";
    
    private static final Logger LOG = Logger.getLogger(UserResources.class.getName());
    private final Datastore datastore = DatastoreOptions.getDefaultInstance().getService();
    
    private static final List<String> VALID_ROLES = Arrays.asList(ROLE_ENDUSER, ROLE_BACKOFFICE, ROLE_ADMIN, ROLE_PARTNER);
    private static final List<String> VALID_ACCOUNT_STATES = Arrays.asList(ACCOUNT_STATE_ACTIVATED, ACCOUNT_STATE_DEACTIVATED, ACCOUNT_STATE_SUSPENDED);

    // Método auxiliar para verificar token e role
    private Entity validateTokenAndRole(String token, String... allowedRoles) {
        if (token == null || token.isEmpty()) {
            throw new WebApplicationException(
                Response.status(Status.UNAUTHORIZED).entity("{\"error\": \"Token de autenticação necessário\"}").build());
        }

        Key tokenKey = datastore.newKeyFactory().setKind("AuthToken").newKey(token);
        Entity tokenEntity = datastore.get(tokenKey);
        
        if (tokenEntity == null) {
            throw new WebApplicationException(
                Response.status(Status.UNAUTHORIZED).entity("{\"error\": \"Token inválido\"}").build());
        }

        // Verificar se o token expirou
        long validTo = tokenEntity.getLong("validTo");
        if (System.currentTimeMillis() > validTo) {
            throw new WebApplicationException(
                Response.status(Status.UNAUTHORIZED).entity("{\"error\": \"Token expirado\"}").build());
        }

        // Verificar role
        String userRole = tokenEntity.getString("role");
        if (allowedRoles.length > 0 && !Arrays.asList(allowedRoles).contains(userRole)) {
            throw new WebApplicationException(
                Response.status(Status.FORBIDDEN).entity("{\"error\": \"Acesso não autorizado para o seu perfil\"}").build());
        }

        return tokenEntity;
    }

    @POST
    @Path("/register")
    @Consumes(MediaType.APPLICATION_JSON)
    @Produces(MediaType.APPLICATION_JSON)
    public Response registerUser(User user) {
        try {
            // Validações do utilizador (mantidas como estavam)
            if (user.getEmail() == null || !user.getEmail().contains("@")) {
                return Response.status(Status.BAD_REQUEST)
                    .entity("{\"error\": \"Email inválido\"}").build();
            }
            if (user.getPassword() == null || user.getPassword().length() < 6) {
                return Response.status(Status.BAD_REQUEST)
                    .entity("{\"error\": \"Password deve ter pelo menos 6 caracteres\"}").build();
            }

            Key userKey = datastore.newKeyFactory().setKind("User").newKey(user.getUsername());
            Entity existingUser = datastore.get(userKey);
            if (existingUser != null) {
                return Response.status(Status.BAD_REQUEST)
                    .entity("{\"error\": \"Username já existe\"}").build();
            }

            // Criação do utilizador com role padrão ENDUSER e estado DESATIVADA
            Entity userEntity = Entity.newBuilder(userKey)
                .set(PROP_EMAIL, user.getEmail())
                .set(PROP_USERNAME, user.getUsername())
                .set(PROP_FULLNAME, user.getFullName())
                .set(PROP_PHONE, user.getPhone())
                .set(PROP_PASSWORD, DigestUtils.sha512Hex(user.getPassword()))
                .set(PROP_PROFILE, user.getProfile())
                .set(PROP_ROLE, user.getRole() != null ? user.getRole() : ROLE_ENDUSER)
                .set(PROP_ACCOUNT_STATE, user.getAccountState() != null ? user.getAccountState() : ACCOUNT_STATE_DEACTIVATED)
                .build();

            datastore.put(userEntity);
            return Response.ok("{\"message\": \"Utilizador registado com sucesso\"}").build();
            
        } catch (Exception e) {
            return Response.serverError()
                .entity("{\"error\": \"Erro ao registar utilizador: " + e.getMessage() + "\"}").build();
        }
    }

    @POST
    @Path("/change-role")
    @Consumes(MediaType.APPLICATION_JSON)
    @Produces(MediaType.APPLICATION_JSON)
    public Response changeRole(
        @HeaderParam("Authorization") String token,
        @QueryParam("target") String targetUsername,
        @QueryParam("newRole") String newRole) {

        try {
            // Verificar token e role (apenas ADMIN pode mudar roles)
            Entity tokenEntity = validateTokenAndRole(token, ROLE_ADMIN);
            String requesterUsername = tokenEntity.getString(PROP_USERNAME);

            // Validação do novo role
            if (!VALID_ROLES.contains(newRole)) {
                return Response.status(Status.BAD_REQUEST)
                    .entity("{\"error\": \"Perfil inválido. Valores permitidos: " + VALID_ROLES + "\"}").build();
            }

            // Verificar utilizador alvo
            Key targetKey = datastore.newKeyFactory().setKind("User").newKey(targetUsername);
            Entity targetUser = datastore.get(targetKey);
            if (targetUser == null) {
                return Response.status(Status.NOT_FOUND)
                    .entity("{\"error\": \"Utilizador não encontrado\"}").build();
            }

            // Atualizar role
            Entity updatedUser = Entity.newBuilder(targetUser)
                .set(PROP_ROLE, newRole)
                .build();

            Transaction txn = datastore.newTransaction();
            try {
                txn.update(updatedUser);
                txn.commit();
                return Response.ok("{\"message\": \"Perfil atualizado com sucesso\"}").build();
            } finally {
                if (txn.isActive()) txn.rollback();
            }
        } catch (WebApplicationException e) {
            return e.getResponse();
        } catch (Exception e) {
            return Response.serverError()
                .entity("{\"error\": \"Falha ao atualizar perfil: " + e.getMessage() + "\"}").build();
        }
    }
    
    @POST
    @Path("/change-account-state")
    @Consumes(MediaType.APPLICATION_JSON)
    @Produces(MediaType.APPLICATION_JSON)
    public Response changeAccountState(
        @HeaderParam("Authorization") String token,
        @QueryParam("target") String targetUsername,
        @QueryParam("newState") String newState) {

        try {
            // Verificar token e roles permitidos (ADMIN ou BACKOFFICE)
            Entity tokenEntity = validateTokenAndRole(token, ROLE_ADMIN, ROLE_BACKOFFICE);
            String requesterRole = tokenEntity.getString("role");

            // Validação do novo estado
            if (!VALID_ACCOUNT_STATES.contains(newState)) {
                return Response.status(Status.BAD_REQUEST)
                    .entity("{\"error\": \"Estado inválido. Valores permitidos: " + VALID_ACCOUNT_STATES + "\"}").build();
            }

            // Verificar utilizador alvo
            Key targetKey = datastore.newKeyFactory().setKind("User").newKey(targetUsername);
            Entity targetUser = datastore.get(targetKey);
            if (targetUser == null) {
                return Response.status(Status.NOT_FOUND)
                    .entity("{\"error\": \"Utilizador não encontrado\"}").build();
            }

            String currentState = targetUser.getString(PROP_ACCOUNT_STATE);
            
            // Verificar se o estado já é o pretendido
            if (currentState.equals(newState)) {
                return Response.status(Status.BAD_REQUEST)
                    .entity("{\"error\": \"A conta já está no estado solicitado\"}").build();
            }

            // Verificar permissões específicas
            if (ROLE_BACKOFFICE.equals(requesterRole)) {
                // BACKOFFICE só pode ativar/desativar (não pode suspender)
                if (!((ACCOUNT_STATE_ACTIVATED.equals(currentState) && ACCOUNT_STATE_DEACTIVATED.equals(newState)) ||
                     (ACCOUNT_STATE_DEACTIVATED.equals(currentState) && ACCOUNT_STATE_ACTIVATED.equals(newState)))) {
                    return Response.status(Status.FORBIDDEN)
                        .entity("{\"error\": \"BACKOFFICE só pode ativar/desativar contas\"}").build();
                }
            }

            // Atualizar estado da conta
            Entity updatedUser = Entity.newBuilder(targetUser)
                .set(PROP_ACCOUNT_STATE, newState)
                .build();

            Transaction txn = datastore.newTransaction();
            try {
                txn.update(updatedUser);
                txn.commit();
                return Response.ok("{\"message\": \"Estado da conta atualizado com sucesso\"}").build();
            } finally {
                if (txn.isActive()) txn.rollback();
            }
        } catch (WebApplicationException e) {
            return e.getResponse();
        } catch (Exception e) {
            return Response.serverError()
                .entity("{\"error\": \"Falha ao atualizar estado da conta: " + e.getMessage() + "\"}").build();
        }
    }

    @POST
    @Path("/remove-user")
    @Consumes(MediaType.APPLICATION_JSON)
    @Produces(MediaType.APPLICATION_JSON)
    public Response removeUserAccount(
        @HeaderParam("Authorization") String token,
        @QueryParam("target") String targetUsername) {

        try {
            // Verificar token e role (apenas ADMIN pode remover contas)
            Entity tokenEntity = validateTokenAndRole(token, ROLE_ADMIN);

            // Verificar utilizador alvo
            Key targetKey = datastore.newKeyFactory().setKind("User").newKey(targetUsername);
            Entity targetUser = datastore.get(targetKey);
            if (targetUser == null) {
                return Response.status(Status.NOT_FOUND)
                    .entity("{\"error\": \"Utilizador não encontrado\"}").build();
            }

            // Remover utilizador
            Transaction txn = datastore.newTransaction();
            try {
                txn.delete(targetKey);
                txn.commit();
                return Response.ok("{\"message\": \"Conta removida com sucesso\"}").build();
            } finally {
                if (txn.isActive()) txn.rollback();
            }
        } catch (WebApplicationException e) {
            return e.getResponse();
        } catch (Exception e) {
            return Response.serverError()
                .entity("{\"error\": \"Falha ao remover conta: " + e.getMessage() + "\"}").build();
        }
    }

    @PostConstruct
    public void initRootUser() {
        Transaction txn = datastore.newTransaction();
        try {
            Key rootKey = datastore.newKeyFactory().setKind("User").newKey("root");
            if (txn.get(rootKey) == null) {
                Entity rootUser = Entity.newBuilder(rootKey)
                    .set(PROP_EMAIL, "root@admin.adc")
                    .set(PROP_USERNAME, "root")
                    .set(PROP_FULLNAME, "Root Administrator")
                    .set(PROP_PHONE, "+351000000000")
                    .set(PROP_PASSWORD, DigestUtils.sha512Hex("adminPassword123!"))
                    .set(PROP_PROFILE, "private")
                    .set(PROP_ROLE, ROLE_ADMIN)
                    .set(PROP_ACCOUNT_STATE, ACCOUNT_STATE_ACTIVATED)
                    .build();
                
                txn.put(rootUser);
                txn.commit();
                LOG.info("Utilizador root/admin criado com sucesso!");
            }
        } catch (Exception e) {
            if (txn.isActive()) txn.rollback();
            LOG.severe("Erro ao criar root user: " + e.getMessage());
        }
    }
}