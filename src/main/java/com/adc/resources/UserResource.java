package com.adc.resources;

import com.adc.entities.User;
import com.google.cloud.datastore.*;
import jakarta.ws.rs.*;
import jakarta.ws.rs.core.MediaType;
import jakarta.ws.rs.core.Response;
import org.apache.commons.codec.digest.DigestUtils;
import java.util.logging.Logger;

@Path("/users")
public class UserResource {

    private static final Logger LOG = Logger.getLogger(UserResource.class.getName());
    private final Datastore datastore = DatastoreOptions.getDefaultInstance().getService();

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
}
