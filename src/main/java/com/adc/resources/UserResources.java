package com.adc.resources;

import java.util.ArrayList;
import java.util.Arrays;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.logging.Logger;
import java.util.regex.Pattern;

import org.apache.commons.codec.digest.DigestUtils;

import com.adc.entities.User;
import com.google.cloud.datastore.*;
import com.google.cloud.datastore.DatastoreOptions;
import com.google.cloud.datastore.StructuredQuery.PropertyFilter;
import com.google.gson.Gson;

import jakarta.annotation.PostConstruct;
import jakarta.json.Json;
import jakarta.json.JsonArrayBuilder;
import jakarta.json.JsonObjectBuilder;
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
    
    // Estados da conta
    private static final String ACCOUNT_STATE_ACTIVATED = "ATIVADA";
    private static final String ACCOUNT_STATE_DEACTIVATED = "DESATIVADA";
    private static final String ACCOUNT_STATE_SUSPENDED = "SUSPENSA";
    
    // Propriedades
    private static final String PROP_USERNAME = "username";
    private static final String PROP_EMAIL = "email";
    private static final String PROP_FULLNAME = "fullName";
    private static final String PROP_PHONE = "phone";
    private static final String PROP_PASSWORD = "password";
    private static final String PROP_PROFILE = "profile";
    private static final String PROP_ROLE = "role";
    private static final String PROP_ACCOUNT_STATE = "accountState";
    
    private static final Logger LOG = Logger.getLogger(UserResources.class.getName());
    private final Datastore datastore = DatastoreOptions.getDefaultInstance().getService();
    
    private static final List<String> VALID_ROLES = Arrays.asList(ROLE_ENDUSER, ROLE_BACKOFFICE, ROLE_ADMIN, ROLE_PARTNER);
    private static final List<String> VALID_ACCOUNT_STATES = Arrays.asList(ACCOUNT_STATE_ACTIVATED, ACCOUNT_STATE_DEACTIVATED, ACCOUNT_STATE_SUSPENDED);
    private static final List<String> PUBLIC_PROFILES = Arrays.asList("público", "privado");
    
    private static final Pattern EMAIL_PATTERN = Pattern.compile("^[A-Za-z0-9+_.-]+@[A-Za-z0-9.-]+\\.[A-Za-z]{2,}$");
    private static final Pattern PASSWORD_PATTERN = Pattern.compile("^(?=.*[0-9])(?=.*[a-z])(?=.*[A-Z])(?=.*[@#$%^&+=!])(?=\\S+$).{8,}$");

  
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

        long validTo = tokenEntity.getLong("validTo");
        if (System.currentTimeMillis() > validTo) {
            throw new WebApplicationException(
                Response.status(Status.UNAUTHORIZED).entity("{\"error\": \"Token expirado\"}").build());
        }

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
    public Response registerUser(User user, @QueryParam("confirmPassword") String confirmPassword) {
        try {
        	
            if (user.getEmail() == null || !EMAIL_PATTERN.matcher(user.getEmail()).matches()) {
                return Response.status(Status.BAD_REQUEST)
                    .entity("{\"error\": \"Email inválido. Deve seguir o formato string@string.domínio\"}").build();
            }
            
            if (user.getPassword() == null || !PASSWORD_PATTERN.matcher(user.getPassword()).matches()) {
                return Response.status(Status.BAD_REQUEST)
                    .entity("{\"error\": \"Password deve conter pelo menos 8 caracteres, incluindo maiúsculas, minúsculas, números e caracteres especiais\"}").build();
            }
            
            if (confirmPassword == null || confirmPassword.isBlank()) {
                return Response.status(Status.ACCEPTED)
                    .entity("{\"message\": \"Todos os dados estão válidos. Por favor, confirme a password para continuar.\"}")
                    .build();
            }
            
            if (!user.getPassword().equals(confirmPassword)) {
                return Response.status(Status.BAD_REQUEST)
                    .entity("{\"error\": \"As passwords não coincidem\"}").build();
            }
            
            if (user.getUsername() == null || user.getUsername().isEmpty()) {
                return Response.status(Status.BAD_REQUEST)
                    .entity("{\"error\": \"Username é obrigatório\"}").build();
            }
            
            if (user.getFullName() == null || user.getFullName().isEmpty()) {
                return Response.status(Status.BAD_REQUEST)
                    .entity("{\"error\": \"Nome completo é obrigatório\"}").build();
            }
            
            if (user.getPhone() == null || user.getPhone().isEmpty()) {
                return Response.status(Status.BAD_REQUEST)
                    .entity("{\"error\": \"Telefone é obrigatório\"}").build();
            }
            
            if (user.getProfile() == null || !PUBLIC_PROFILES.contains(user.getProfile())) {
                return Response.status(Status.BAD_REQUEST)
                    .entity("{\"error\": \"Perfil deve ser 'público' ou 'privado'\"}").build();
            }

            Key userKey = datastore.newKeyFactory().setKind("User").newKey(user.getUsername());
            Entity existingUser = datastore.get(userKey);
            if (existingUser != null) {
                return Response.status(Status.BAD_REQUEST)
                    .entity("{\"error\": \"Username já existe\"}").build();
            }
            
            Query<Entity> emailQuery = Query.newEntityQueryBuilder()
                .setKind("User")
                .setFilter(PropertyFilter.eq(PROP_EMAIL, user.getEmail()))
                .build();
            
            if (datastore.run(emailQuery).hasNext()) {
                return Response.status(Status.BAD_REQUEST)
                    .entity("{\"error\": \"Email já registado\"}").build();
            }
            
            Query<Entity> phoneQuery = Query.newEntityQueryBuilder()
                .setKind("User")
                .setFilter(PropertyFilter.eq(PROP_PHONE, user.getPhone()))
                .build();
            
            if (datastore.run(phoneQuery).hasNext()) {
                return Response.status(Status.BAD_REQUEST)
                    .entity("{\"error\": \"Número de telefone já registado\"}").build();
            }

            Entity userEntity = Entity.newBuilder(userKey)
                .set(PROP_EMAIL, user.getEmail())
                .set(PROP_USERNAME, user.getUsername())
                .set(PROP_FULLNAME, user.getFullName())
                .set(PROP_PHONE, user.getPhone())
                .set(PROP_PASSWORD, DigestUtils.sha512Hex(user.getPassword()))
                .set(PROP_PROFILE, user.getProfile())
                .set(PROP_ROLE, ROLE_ENDUSER) 
                .set(PROP_ACCOUNT_STATE, ACCOUNT_STATE_DEACTIVATED) 
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
            // Verificar token e role (ADMIN ou BACKOFFICE)
            Entity tokenEntity = validateTokenAndRole(token, ROLE_ADMIN, ROLE_BACKOFFICE);
            String requesterRole = tokenEntity.getString("role");

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

            String currentRole = targetUser.getString(PROP_ROLE);
            
            // Verificar regras de mudança de role conforme enunciado
            if (ROLE_BACKOFFICE.equals(requesterRole)) {
                // BACKOFFICE só pode mudar ENDUSER <-> PARTNER
                if (!((ROLE_ENDUSER.equals(currentRole) && ROLE_PARTNER.equals(newRole)) || 
                     (ROLE_PARTNER.equals(currentRole) && ROLE_ENDUSER.equals(newRole)))) {
                    return Response.status(Status.FORBIDDEN)
                        .entity("{\"error\": \"BACKOFFICE só pode mudar ENDUSER para PARTNER e vice-versa\"}").build();
                }
            }

            // ADMIN pode fazer qualquer mudança, então não precisa de verificação adicional

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
            Entity tokenEntity = validateTokenAndRole(token, ROLE_ADMIN, ROLE_BACKOFFICE);
            String requesterRole = tokenEntity.getString("role");

            if (!VALID_ACCOUNT_STATES.contains(newState)) {
                return Response.status(Status.BAD_REQUEST)
                    .entity("{\"error\": \"Estado inválido. Valores permitidos: " + VALID_ACCOUNT_STATES + "\"}").build();
            }

            Key targetKey = datastore.newKeyFactory().setKind("User").newKey(targetUsername);
            Entity targetUser = datastore.get(targetKey);
            if (targetUser == null) {
                return Response.status(Status.NOT_FOUND)
                    .entity("{\"error\": \"Utilizador não encontrado\"}").build();
            }

            String currentState = targetUser.getString(PROP_ACCOUNT_STATE);
            
            if (currentState.equals(newState)) {
                return Response.status(Status.BAD_REQUEST)
                    .entity("{\"error\": \"A conta já está no estado solicitado\"}").build();
            }

            if (ROLE_BACKOFFICE.equals(requesterRole)) {
                if (ACCOUNT_STATE_SUSPENDED.equals(newState)) {
                    return Response.status(Status.FORBIDDEN)
                        .entity("{\"error\": \"BACKOFFICE não pode suspender contas\"}").build();
                }
                
                if (!((ACCOUNT_STATE_ACTIVATED.equals(currentState) && ACCOUNT_STATE_DEACTIVATED.equals(newState)) ||
                     (ACCOUNT_STATE_DEACTIVATED.equals(currentState) && ACCOUNT_STATE_ACTIVATED.equals(newState)))) {
                    return Response.status(Status.FORBIDDEN)
                        .entity("{\"error\": \"BACKOFFICE só pode ativar/desativar contas\"}").build();
                }
            }

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
    @Path("/remove")
    @Consumes(MediaType.APPLICATION_JSON)
    @Produces(MediaType.APPLICATION_JSON)
    public Response removeUserAccount(
        @HeaderParam("Authorization") String token,
        @QueryParam("target") String targetUsername) {

        try {
            Entity tokenEntity = validateTokenAndRole(token, ROLE_ADMIN, ROLE_BACKOFFICE);
            String requesterRole = tokenEntity.getString("role");

            Key targetKey = datastore.newKeyFactory().setKind("User").newKey(targetUsername);
            Entity targetUser = datastore.get(targetKey);
            if (targetUser == null) {
                return Response.status(Status.NOT_FOUND)
                    .entity("{\"error\": \"Utilizador não encontrado\"}").build();
            }

            if (ROLE_BACKOFFICE.equals(requesterRole)) {
                String targetRole = targetUser.getString(PROP_ROLE);
                if (!ROLE_ENDUSER.equals(targetRole) && !ROLE_PARTNER.equals(targetRole)) {
                    return Response.status(Status.FORBIDDEN)
                        .entity("{\"error\": \"BACKOFFICE só pode remover contas ENDUSER ou PARTNER\"}").build();
                }
            }


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
    
    @POST
    @Path("/list")
    @Consumes(MediaType.APPLICATION_JSON)
    @Produces(MediaType.APPLICATION_JSON)
    public Response listUsers(@HeaderParam("Authorization") String token) {
        try {
            Entity tokenEntity = validateTokenAndRole(token, ROLE_ENDUSER, ROLE_BACKOFFICE, ROLE_ADMIN);
            String requesterRole = tokenEntity.getString("role");

            QueryResults<Entity> users = datastore.run(Query.newEntityQueryBuilder()
                .setKind("User")
                .build());

            List<Map<String, String>> result = new ArrayList<>();

            while (users.hasNext()) {
                Entity user = users.next();
                String userRole = user.getString(PROP_ROLE);
                String accountState = user.getString(PROP_ACCOUNT_STATE);
                String profile = user.getString(PROP_PROFILE);

                // Verificar se o usuário deve ser incluído
                if (requesterRole.equals(ROLE_ADMIN) || 
                    (requesterRole.equals(ROLE_BACKOFFICE) && userRole.equals(ROLE_ENDUSER)) ||
                    (requesterRole.equals(ROLE_ENDUSER) && userRole.equals(ROLE_ENDUSER) && 
                     profile.equals("público") && accountState.equals(ACCOUNT_STATE_ACTIVATED))) {

                    Map<String, String> userData = new HashMap<>();

                    // Campos básicos para todos
                    userData.put("username", user.getString(PROP_USERNAME));
                    userData.put("email", user.getString(PROP_EMAIL));

                    // Se for ADMIN ou BACKOFFICE, adiciona todos os campos
                    if (requesterRole.equals(ROLE_ADMIN) || requesterRole.equals(ROLE_BACKOFFICE)) {
                        userData.put("fullName", getValueOrNotDefined(user, PROP_FULLNAME));
                        userData.put("phone", getValueOrNotDefined(user, PROP_PHONE));
                        userData.put("profile", profile);
                        userData.put("role", userRole);
                        userData.put("accountState", accountState);

                        userData.put("citizenCardNumber", getValueOrNotDefined(user, "citizenCardNumber"));
                        userData.put("nif", getValueOrNotDefined(user, "nif"));
                        userData.put("employer", getValueOrNotDefined(user, "employer"));
                        userData.put("jobTitle", getValueOrNotDefined(user, "jobTitle"));
                        userData.put("address", getValueOrNotDefined(user, "address"));
                        userData.put("employerNif", getValueOrNotDefined(user, "employerNif"));
                    } else {
                        userData.put("fullName", getValueOrNotDefined(user, PROP_FULLNAME));
                    }

                    result.add(userData);
                }
            }

            return Response.ok(new Gson().toJson(result)).build();

        } catch (Exception e) {
            return Response.serverError()
                .entity("{\"error\": \"Erro ao listar usuários: " + e.getMessage() + "\"}")
                .build();
        }
    }

    // tratar campos não definidos
    private String getValueOrNotDefined(Entity user, String property) {
        return user.contains(property) ? user.getString(property) : "NOT DEFINED";
    }

    
    @POST
    @Path("/change-attributes")
    @Consumes(MediaType.APPLICATION_JSON)
    @Produces(MediaType.APPLICATION_JSON)
    public Response changeAccountAttributes(
        @HeaderParam("Authorization") String token,
        @QueryParam("target") String targetUsername,
        Map<String, String> attributes) {

        try {
            Entity tokenEntity = validateTokenAndRole(token);
            String requesterRole = tokenEntity.getString("role");
            
            if (targetUsername == null || targetUsername.isEmpty()) {
                return Response.status(Status.BAD_REQUEST)
                    .entity("{\"error\": \"Target username é obrigatório\"}").build();
            }

            Key targetKey = datastore.newKeyFactory().setKind("User").newKey(targetUsername);
            Entity targetUser = datastore.get(targetKey);
            
            if (targetUser == null) {
                return Response.status(Status.NOT_FOUND)
                    .entity("{\"error\": \"Utilizador não encontrado\"}").build();
            }

            String targetRole = targetUser.getString(PROP_ROLE);
            
            if (requesterRole.equals(ROLE_ENDUSER)) {
                

                if (!targetUser.getString(PROP_USERNAME).equals(targetUsername)) {
                    return Response.status(Status.FORBIDDEN)
                        .entity("{\"error\": \"Só pode modificar sua própria conta\"}").build();
                }
                attributes.keySet().removeAll(Arrays.asList(PROP_USERNAME, PROP_EMAIL, PROP_FULLNAME, PROP_ROLE, PROP_ACCOUNT_STATE));
            } 
            else if (requesterRole.equals(ROLE_BACKOFFICE)) {
                if (!Arrays.asList(ROLE_ENDUSER, ROLE_PARTNER).contains(targetRole)) {
                    return Response.status(Status.FORBIDDEN)
                        .entity("{\"error\": \"Só pode modificar contas ENDUSER/PARTNER\"}").build();
                }
                attributes.remove(PROP_USERNAME);
                attributes.remove(PROP_EMAIL);
            }

            Entity.Builder updatedUser = Entity.newBuilder(targetUser);
            for (Map.Entry<String, String> entry : attributes.entrySet()) {
                if (!entry.getKey().equals(PROP_PASSWORD)) {
                    updatedUser.set(entry.getKey(), entry.getValue());
                }
            }

            Transaction txn = datastore.newTransaction();
            try {
                txn.update(updatedUser.build());
                txn.commit();
                return Response.ok("{\"message\": \"Atributos atualizados com sucesso\"}").build();
            } finally {
                if (txn.isActive()) txn.rollback();
            }
        } catch (Exception e) {
            return Response.serverError()
                .entity("{\"error\": \"Falha na atualização: " + e.getMessage() + "\"}").build();
        }
    }

    
    @POST
    @Path("/change-password")
    @Consumes(MediaType.APPLICATION_JSON)
    @Produces(MediaType.APPLICATION_JSON)
    public Response changePassword(
        @HeaderParam("Authorization") String token,
        @QueryParam("currentPassword") String currentPassword,
        @QueryParam("newPassword") String newPassword,
        @QueryParam("confirmPassword") String confirmPassword) {

        try {
            Entity tokenEntity = validateTokenAndRole(token);
            String username = tokenEntity.getString("username"); 
            
            Key userKey = datastore.newKeyFactory().setKind("User").newKey(username);
            Entity user = datastore.get(userKey);
            
            if (user == null) {
                return Response.status(Status.NOT_FOUND)
                    .entity("{\"error\": \"Utilizador não encontrado\"}").build();
            }

            String storedHash = user.getString(PROP_PASSWORD);
            if (!storedHash.equals(DigestUtils.sha512Hex(currentPassword))) {
                return Response.status(Status.UNAUTHORIZED)
                    .entity("{\"error\": \"Senha atual incorreta\"}").build();
            }

            if (!newPassword.equals(confirmPassword)) {
                return Response.status(Status.BAD_REQUEST)
                    .entity("{\"error\": \"As senhas não coincidem\"}").build();
            }

            if (!PASSWORD_PATTERN.matcher(newPassword).matches()) {
                return Response.status(Status.BAD_REQUEST)
                    .entity("{\"error\": \"Nova senha não cumpre requisitos\"}").build();
            }

            Entity updatedUser = Entity.newBuilder(user)
                .set(PROP_PASSWORD, DigestUtils.sha512Hex(newPassword))
                .build();

            Transaction txn = datastore.newTransaction();
            try {
                txn.update(updatedUser);
                txn.commit();
                return Response.ok("{\"message\": \"Senha alterada com sucesso\"}").build();
            } finally {
                if (txn.isActive()) txn.rollback();
            }
        } catch (Exception e) {
            return Response.serverError()
                .entity("{\"error\": \"Falha ao alterar senha: " + e.getMessage() + "\"}").build();
        }
    }
    
    @POST
    @Path("/logout")
    @Consumes(MediaType.APPLICATION_JSON)
    @Produces(MediaType.APPLICATION_JSON)
    public Response logout(@HeaderParam("Authorization") String token) {
        try {
            if (token == null || token.isEmpty()) {
                return Response.status(Status.BAD_REQUEST)
                    .entity("{\"error\": \"Token não fornecido\"}").build();
            }

            Key tokenKey = datastore.newKeyFactory().setKind("AuthToken").newKey(token);
            
            Entity tokenEntity = datastore.get(tokenKey);
            if (tokenEntity == null) {
                return Response.status(Status.NOT_FOUND)
                    .entity("{\"error\": \"Token já invalidado ou inexistente\"}").build();
            }

            Transaction txn = datastore.newTransaction();
            try {
                txn.delete(tokenKey);
                txn.commit();
                LOG.info("Token invalidado com sucesso: " + token);
                return Response.ok("{\"message\": \"Logout realizado com sucesso\"}").build();
            } finally {
                if (txn.isActive()) {
                    txn.rollback();
                }
            }
        } catch (Exception e) {
            LOG.severe("Erro durante logout: " + e.getMessage());
            return Response.serverError()
                .entity("{\"error\": \"Falha no logout: " + e.getMessage() + "\"}").build();
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
                    .set(PROP_PROFILE, "privado")
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