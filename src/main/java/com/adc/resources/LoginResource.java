package com.adc.resources;

import com.adc.util.AuthToken;
import com.adc.util.LoginData;
import com.google.cloud.datastore.*;
import com.google.gson.Gson;
import jakarta.ws.rs.*;
import jakarta.ws.rs.core.MediaType;
import jakarta.ws.rs.core.Response;
import jakarta.ws.rs.core.Response.Status;
import org.apache.commons.codec.digest.DigestUtils;

@Path("/users")
public class LoginResource {
    private final Datastore datastore = DatastoreOptions.getDefaultInstance().getService();
    private final Gson gson = new Gson();

    @POST
    @Path("/login")
    @Consumes(MediaType.APPLICATION_JSON)
    @Produces(MediaType.APPLICATION_JSON)
    public Response doLogin(LoginData data) {
        try {
            // 1. Determinar se o login é email ou username
            boolean isEmail = data.login.contains("@");
            
            // 2. Buscar o utilizador na base de dados
            Entity user = findUser(data.login, isEmail);
            
            if (user == null) {
                return Response.status(Status.FORBIDDEN)
                    .entity("{\"error\": \"Credenciais inválidas\"}").build();
            }

            // 3. Validar a palavra-passe
            String hashedPWD = user.getString("password");
            if (!hashedPWD.equals(DigestUtils.sha512Hex(data.password))) {
                return Response.status(Status.FORBIDDEN)
                    .entity("{\"error\": \"Credenciais inválidas\"}").build();
            }

            // 4. Verificar se a conta está ativada
            String accountState = user.getString("accountState");
            if (!"ATIVADA".equals(accountState)) {
                return Response.status(Status.FORBIDDEN)
                    .entity("{\"error\": \"Conta não ativada. Estado atual: " + accountState + "\"}")
                    .build();
            }

            // 5. Obter o perfil do utilizador
            String userRole = user.getString("role");
            String username = user.getString("username");

            // 6. Criar token de autenticação
            AuthToken token = new AuthToken(username, userRole);

            // 7. Guardar o token na base de dados
            Key tokenKey = datastore.newKeyFactory().setKind("AuthToken").newKey(token.tokenID);
            Entity tokenEntity = Entity.newBuilder(tokenKey)
                .set("username", token.USER)
                .set("role", token.ROLE)
                .set("validFrom", token.VALIDITY.VALID_FROM)
                .set("validTo", token.VALIDITY.VALID_TO)
                .set("verificador", token.VERIFIER)
                .build();
            
            datastore.put(tokenEntity);

            // 8. Retornar resposta
            String welcomeMessage = generateWelcomeMessage(userRole);
            return Response.ok()
                .entity("{\"token\": " + gson.toJson(token) + ", \"message\": \"" + welcomeMessage + "\"}")
                .build();

        } catch (Exception e) {
            return Response.serverError()
                .entity("{\"error\": \"Ocorreu um erro durante o login: " + e.getMessage() + "\"}")
                .build();
        }
    }

    private Entity findUser(String login, boolean isEmail) {
        Query<Entity> query;
        
        if (isEmail) {
            // Buscar por email
            query = Query.newEntityQueryBuilder()
                .setKind("User")
                .setFilter(StructuredQuery.PropertyFilter.eq("email", login))
                .build();
        } else {
            // Buscar por username (chave primária)
            Key userKey = datastore.newKeyFactory().setKind("User").newKey(login);
            return datastore.get(userKey);
        }
        
        QueryResults<Entity> results = datastore.run(query);
        return results.hasNext() ? results.next() : null;
    }

    private String generateWelcomeMessage(String role) {
        switch (role) {
            case "ADMIN":
                return "Sessão iniciada como Administrador";
            case "BACKOFFICE":
                return "Sessão iniciada como Utilizador de Backoffice";
            case "PARTNER":
                return "Sessão iniciada como Parceiro";
            case "ENDUSER":
            default:
                return "Sessão iniciada como Utilizador";
        }
    }
}