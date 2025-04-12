package com.adc.resources;

import com.adc.entities.User;
import com.google.cloud.datastore.*;

import jakarta.annotation.PostConstruct;
import jakarta.ws.rs.*;
import jakarta.ws.rs.core.MediaType;
import jakarta.ws.rs.core.Response;
import jakarta.ws.rs.core.Response.Status;
import org.apache.commons.codec.digest.DigestUtils;
import java.util.logging.Logger;
import java.util.Arrays;
import java.util.List;

@Path("/users")
public class UserResources {

    private static final Logger LOG = Logger.getLogger(UserResources.class.getName());
    private final Datastore datastore = DatastoreOptions.getDefaultInstance().getService();
    private static final List<String> VALID_ROLES = Arrays.asList("ENDUSER", "BACKOFFICE", "ADMIN", "PARTNER");

    @POST
    @Path("/register")
    @Consumes(MediaType.APPLICATION_JSON)
    @Produces(MediaType.APPLICATION_JSON)
    public Response registerUser(User user) {

        try {
            // Validações obrigatórias
            if (user.getEmail() == null || !user.getEmail().contains("@")) {
                LOG.warning("Email inválido: " + user.getEmail());
                return Response.status(Response.Status.BAD_REQUEST)
                    .entity("{\"error\": \"Email inválido\"}").build();
            }
            if (user.getPassword() == null || user.getPassword().length() < 6) {
                LOG.warning("Senha muito curta para o usuário: " + user.getUsername());
                return Response.status(Response.Status.BAD_REQUEST)
                    .entity("{\"error\": \"Senha deve ter pelo menos 6 caracteres\"}").build();
            }

            Key userKey = datastore.newKeyFactory().setKind("User").newKey(user.getUsername());
            Entity existingUser = datastore.get(userKey);
            if (existingUser != null) {
                LOG.warning("Usuário já existe: " + user.getUsername());
                return Response.status(Response.Status.BAD_REQUEST)
                    .entity("{\"error\": \"Username já existe\"}").build();
            }

            Entity userEntity = Entity.newBuilder(userKey)
                .set("email", user.getEmail())
                .set("username", user.getUsername())
                .set("fullName", user.getFullName())
                .set("phone", user.getPhone())
                .set("password", DigestUtils.sha512Hex(user.getPassword()))
                .set("profile", user.getProfile())
                .set("role", user.getRole())
                .set("accountState", user.getAccountState())
                .build();

            datastore.put(userEntity);
            LOG.info("Usuário registrado com sucesso: " + user.getUsername());

            return Response.ok("{\"message\": \"Usuário registrado com sucesso\"}").build();
        } catch (DatastoreException e) {
            LOG.severe("Erro ao acessar o Datastore: " + e.getMessage());
            return Response.serverError().entity("{\"error\": \"Erro ao acessar o Datastore: " + e.getMessage() + "\"}").build();
        } catch (Exception e) {
            LOG.severe("Erro inesperado: " + e.getMessage());
            return Response.serverError().entity("{\"error\": \"Erro inesperado: " + e.getMessage() + "\"}").build();
        }
    }

    @PostConstruct // Executa quando a aplicação inicia
    public void initRootUser() {
        Transaction txn = datastore.newTransaction();
        Key rootKey = datastore.newKeyFactory().setKind("User").newKey("root");
        Entity rootUser = txn.get(rootKey);
            
            if (rootUser == null) {
                rootUser = Entity.newBuilder(rootKey)
                    .set("email", "root@admin.adc")
                    .set("username", "root")
                    .set("fullName", "Root Administrator")
                    .set("phone", "+351000000000")
                    .set("password", DigestUtils.sha512Hex("adminPassword123!"))
                    .set("profile", "private")
                    .set("role", "ADMIN")
                    .set("accountState", "ATIVADA")
                    .build();
                
                txn.put(rootUser);
                txn.commit();
                System.out.println("Usuário root/admin criado com sucesso!");
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
            Key tokenKey = datastore.newKeyFactory().setKind("AuthToken").newKey(token);
            Entity tokenEntity = datastore.get(tokenKey);
            if (tokenEntity == null) {
                LOG.warning("Token inválido: " + token);
                return Response.status(Status.UNAUTHORIZED)
                    .entity("{\"error\": \"Token inválido\"}").build();
            }

            String requesterUsername = tokenEntity.getString("username");
            Entity requester = datastore.get(
                datastore.newKeyFactory().setKind("User").newKey(requesterUsername)
            );

            if (!"ADMIN".equals(requester.getString("role"))) {
                LOG.warning("Tentativa não autorizada de mudança de role por: " + requesterUsername);
                return Response.status(Status.FORBIDDEN)
                    .entity("{\"error\": \"Apenas ADMIN pode alterar roles\"}").build();
            }

            if (!VALID_ROLES.contains(newRole)) {
                LOG.warning("Role inválida: " + newRole);
                return Response.status(Status.BAD_REQUEST)
                    .entity("{\"error\": \"Role inválida. Valores permitidos: " + VALID_ROLES + "\"}").build();
            }

            Key targetKey = datastore.newKeyFactory().setKind("User").newKey(targetUsername);
            Entity targetUser = datastore.get(targetKey);
            if (targetUser == null) {
                LOG.warning("Usuário alvo não encontrado: " + targetUsername);
                return Response.status(Status.NOT_FOUND)
                    .entity("{\"error\": \"Usuário não encontrado\"}").build();
            }

            Entity updatedUser = Entity.newBuilder(targetUser)
                .set("role", newRole)
                .build();

            Transaction txn = datastore.newTransaction();
            try {
                txn.update(updatedUser);
                txn.commit();
                LOG.info("Role atualizada para " + newRole + " no usuário: " + targetUsername);
                return Response.ok("{\"message\": \"Role atualizada com sucesso\"}").build();
            } finally {
                if (txn.isActive()) {
                    txn.rollback();
                }
            }

        } catch (Exception e) {
            LOG.severe("Erro ao alterar role: " + e.getMessage());
            return Response.serverError()
                .entity("{\"error\": \"Falha ao atualizar role: " + e.getMessage() + "\"}").build();
        }
    }
}

