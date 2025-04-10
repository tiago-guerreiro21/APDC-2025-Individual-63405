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


@Path("/login")
public class LoginResource {
    private final Datastore datastore = DatastoreOptions.getDefaultInstance().getService();
    private final Gson gson = new Gson();

    @POST
    @Path("/")
    @Consumes(MediaType.APPLICATION_JSON)
    @Produces(MediaType.APPLICATION_JSON)
    public Response doLogin(LoginData data) {
        try {
            Key userKey = datastore.newKeyFactory().setKind("User").newKey(data.username);
            Entity user = datastore.get(userKey);

            if (user == null) {
                return Response.status(Status.FORBIDDEN).entity("{\"error\": \"Credenciais inválidas\"}").build();
            }

            String hashedPWD = user.getString("password");
            if (hashedPWD.equals(DigestUtils.sha512Hex(data.password))) {
                AuthToken token = new AuthToken(data.username);

                // Persistir o token no Datastore
                Key tokenKey = datastore.newKeyFactory().setKind("AuthToken").newKey(token.tokenID);
                Entity tokenEntity = Entity.newBuilder(tokenKey)
                    .set("username", data.username)
                    .set("expirationData", token.expirationData)
                    .build();
                datastore.put(tokenEntity);

                return Response.ok(gson.toJson(token)).build();
            } else {
                return Response.status(Status.FORBIDDEN).entity("{\"error\": \"Senha incorreta\"}").build();
            }
        } catch (Exception e) {
            return Response.serverError().entity("{\"error\": \"Erro interno\"}").build();
        }
    }
}