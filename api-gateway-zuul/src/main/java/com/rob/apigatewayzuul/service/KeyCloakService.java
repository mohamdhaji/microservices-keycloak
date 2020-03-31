package com.rob.apigatewayzuul.service;


import com.rob.apigatewayzuul.model.UserCredentials;
import com.rob.apigatewayzuul.model.UserDTO;
import org.apache.commons.lang3.StringUtils;
import org.apache.http.HttpResponse;
import org.apache.http.NameValuePair;
import org.apache.http.client.HttpClient;
import org.apache.http.client.entity.UrlEncodedFormEntity;
import org.apache.http.client.methods.HttpPost;
import org.apache.http.impl.client.HttpClientBuilder;
import org.apache.http.message.BasicNameValuePair;
import org.jboss.logging.Logger;
import org.jboss.resteasy.client.jaxrs.ResteasyClientBuilder;
import org.keycloak.adapters.KeycloakDeployment;
import org.keycloak.adapters.KeycloakDeploymentBuilder;
import org.keycloak.adapters.OIDCAuthenticationError;
import org.keycloak.adapters.OIDCHttpFacade;
import org.keycloak.adapters.rotation.AdapterTokenVerifier;
import org.keycloak.adapters.spi.AuthChallenge;
import org.keycloak.adapters.spi.AuthOutcome;
import org.keycloak.adapters.spi.HttpFacade;
import org.keycloak.admin.client.Keycloak;
import org.keycloak.admin.client.KeycloakBuilder;
import org.keycloak.admin.client.resource.RealmResource;
import org.keycloak.admin.client.resource.UsersResource;
import org.keycloak.common.VerificationException;
import org.keycloak.jose.jws.JWSInput;
import org.keycloak.jose.jws.JWSInputException;
import org.keycloak.representations.AccessToken;
import org.keycloak.representations.adapters.config.AdapterConfig;
import org.keycloak.representations.idm.CredentialRepresentation;
import org.keycloak.representations.idm.RoleRepresentation;
import org.keycloak.representations.idm.UserRepresentation;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.context.ApplicationContext;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.stereotype.Component;

import javax.security.cert.X509Certificate;
import javax.servlet.http.HttpServletRequest;
import javax.ws.rs.core.Response;
import java.io.BufferedReader;
import java.io.InputStreamReader;
import java.util.*;

@Component
public class KeyCloakService {

    @Value("${keycloak.credentials.secret}")
    private String SECRETKEY;

    @Value("${keycloak.resource}")
    private String CLIENTID;

    @Value("${keycloak.auth-server-url}")
    private String AUTHURL;

    @Value("${keycloak.realm}")
    private String REALM;

    @Autowired
    protected KeycloakDeployment deployment;

    @Autowired
    private ApplicationContext environment;

    protected Logger log = Logger.getLogger(KeyCloakService.class);
    protected String tokenString;
    protected AccessToken token;
    protected String surrogate;
    protected AuthChallenge challenge;

    public String getToken(UserCredentials userCredentials) {

        String responseToken = null;
        try {

            String username = userCredentials.getUsername();

            System.out.println(username);
            System.out.println(userCredentials.getPassword() + "");

            List<NameValuePair> urlParameters = new ArrayList<NameValuePair>();
            urlParameters.add(new BasicNameValuePair("grant_type", "password"));
            urlParameters.add(new BasicNameValuePair("client_id", CLIENTID));
            urlParameters.add(new BasicNameValuePair("username", username));
            urlParameters.add(new BasicNameValuePair("password", userCredentials.getPassword()));
            urlParameters.add(new BasicNameValuePair("client_secret", SECRETKEY));

            responseToken = sendPost(urlParameters);

        } catch (Exception e) {
            System.out.println("catch called");

            e.printStackTrace();
        }

        return responseToken;

    }

    public String getByRefreshToken(String refreshToken) {

        String responseToken = null;
        try {

            List<NameValuePair> urlParameters = new ArrayList<NameValuePair>();
            urlParameters.add(new BasicNameValuePair("grant_type", "refresh_token"));
            urlParameters.add(new BasicNameValuePair("client_id", CLIENTID));
            urlParameters.add(new BasicNameValuePair("refresh_token", refreshToken));
            urlParameters.add(new BasicNameValuePair("client_secret", SECRETKEY));

            responseToken = sendPost(urlParameters);

        } catch (Exception e) {
            e.printStackTrace();

        }

        return responseToken;
    }

    public ResponseEntity createUserInKeyCloak(UserDTO userDTO) {

        int statusId = 0;
        try {



            UsersResource userRessource = getKeycloakUserResource();

            CredentialRepresentation passwordCred = new CredentialRepresentation();
            passwordCred.setTemporary(false);
            passwordCred.setType(CredentialRepresentation.PASSWORD);
            passwordCred.setValue(userDTO.getPassword());

            UserRepresentation user = new UserRepresentation();
            user.setUsername(userDTO.getUserName());
            user.setEmail(userDTO.getEmailAddress());
            user.setFirstName(userDTO.getFirstName());
            user.setLastName(userDTO.getLastName());
            user.setEnabled(true);


//            user.setCredentials(Collections.singletonList(passwordCred));


            // Create user
			Response result = userRessource.create(user);



            statusId = result.getStatus();

            System.out.println(statusId);


			if (statusId == 201) {


                String userId = result.getLocation().getPath().replaceAll(".*/([^/]+)$", "$1");

                System.out.println("User created with userId:" + userId);


				// set role
                RealmResource realmResource = getRealmResource();

//                 Get realm role "user" (requires view-realm role)
                RoleRepresentation userRealmRole = realmResource.roles()
                        .get("user").toRepresentation();

				userRessource.get(userId).roles().realmLevel().add(Arrays.asList(userRealmRole));



				userRessource.get(userId).resetPassword(passwordCred);



                System.out.println("Username==" + userDTO.getUserName() + " created in keycloak successfully");

                return new ResponseEntity<>("Username==" + userDTO.getUserName() + " created in keycloak successfully", HttpStatus.CREATED);


            } else if (statusId == 409) {

                System.out.println("Username==" + userDTO.getUserName() + " already present in keycloak");
                return new ResponseEntity<>("Username==" + userDTO.getUserName() + " already present in keycloak", HttpStatus.CONFLICT);


            } else {
                System.out.println("Username==" + userDTO.getUserName() + " could not be created in keycloak");
                return new ResponseEntity<>("Username==" + userDTO.getUserName() + " could not be created in keycloak", HttpStatus.BAD_REQUEST);


            }

        } catch (Exception e) {

            e.printStackTrace();

        }
        return new ResponseEntity<>("Username==" + userDTO.getUserName() + " could not be created in keycloak", HttpStatus.BAD_REQUEST);



    }

    // after logout user from the keycloak system. No new access token will be
    // issued.
    public void logoutUser(String userId) {

        UsersResource userRessource = getKeycloakUserResource();

        userRessource.get(userId).logout();

    }

    // Reset passowrd
    public void resetPassword(String newPassword, String userId) {

        UsersResource userResource = getKeycloakUserResource();

        // Define password credential
        CredentialRepresentation passwordCred = new CredentialRepresentation();
        passwordCred.setTemporary(false);
        passwordCred.setType(CredentialRepresentation.PASSWORD);
        passwordCred.setValue(newPassword.toString().trim());

        // Set password credential
        userResource.get(userId).resetPassword(passwordCred);

    }

    private UsersResource getKeycloakUserResource() {

        Keycloak kc = KeycloakBuilder.builder().serverUrl(AUTHURL).realm("master").username("adminn").password("Pa55w0rd")
                .clientId("admin-cli").resteasyClient(new ResteasyClientBuilder().connectionPoolSize(10).build())
                .build();


        RealmResource realmResource = kc.realm(REALM);
        UsersResource userRessource = realmResource.users();

        return userRessource;
    }

    private RealmResource getRealmResource() {

        Keycloak kc = KeycloakBuilder.builder().serverUrl(AUTHURL).realm("master").username("adminn").password("Pa55w0rd")
                .clientId("admin-cli").resteasyClient(new ResteasyClientBuilder().connectionPoolSize(10).build())
                .build();

        RealmResource realmResource = kc.realm(REALM);

        return realmResource;

    }

    private String sendPost(List<NameValuePair> urlParameters) throws Exception {

        HttpClient client = HttpClientBuilder.create().build();
        HttpPost post = new HttpPost(AUTHURL + "/realms/" + REALM + "/protocol/openid-connect/token");

        post.setEntity(new UrlEncodedFormEntity(urlParameters));

        HttpResponse response = client.execute(post);

        BufferedReader rd = new BufferedReader(new InputStreamReader(response.getEntity().getContent()));

        StringBuffer result = new StringBuffer();
        String line = "";
        while ((line = rd.readLine()) != null) {
            result.append(line);
        }

        return result.toString();

    }


    public AuthChallenge getChallenge() {
        return challenge;
    }

    public String getTokenString() {
        return tokenString;
    }

    public AccessToken getToken() {
        return token;
    }

    public String getSurrogate() {
        return surrogate;
    }

    public AuthOutcome authenticate(HttpServletRequest exchange) {

        String header_authorization = exchange.getHeader("Authorization");

        List<String> authHeaders = (StringUtils.isBlank(header_authorization)) ? null : Arrays.asList(header_authorization);
        if (authHeaders == null || authHeaders.isEmpty()) {
            challenge = challengeResponse(exchange, OIDCAuthenticationError.Reason.NO_BEARER_TOKEN, null, null);
            return AuthOutcome.NOT_ATTEMPTED;
        }


        tokenString = null;
        for (String authHeader : authHeaders) {
            System.out.println(authHeader);
            String[] split = authHeader.trim().split("\\s+");
            if (split.length != 2) continue;
            if (split[0].equalsIgnoreCase("Bearer")) {

                tokenString = split[1];

                log.debugf("Found [%d] values in authorization header, selecting the first value for Bearer.", (Integer) authHeaders.size());
                break;
            }
        }

        if (tokenString == null) {

            challenge = challengeResponse(exchange, OIDCAuthenticationError.Reason.NO_BEARER_TOKEN, null, null);
            return AuthOutcome.NOT_ATTEMPTED;
        }

        return (authenticateToken(exchange, tokenString));
    }


    private void init() {
        AdapterConfig cfg = new AdapterConfig();
        cfg.setRealm(environment.getEnvironment().getProperty("keycloak.realm"));
        cfg.setAuthServerUrl(environment.getEnvironment().getProperty("keycloak.auth-server-url"));
        cfg.setResource(environment.getEnvironment().getProperty("keycloak.resource"));
        Map<String, Object> credentials = new HashMap<>();
        credentials.put("secret", environment.getEnvironment().getProperty("keycloak.credentials-secret"));
        cfg.setCredentials(credentials);

        deployment = KeycloakDeploymentBuilder.build(cfg);

    }

    protected AuthOutcome authenticateToken(HttpServletRequest exchange, String tokenString) {

        init();

        log.debug("Verifying access_token");
//		if (log.isTraceEnabled()) {

        try {
            JWSInput jwsInput = new JWSInput(tokenString);
            String wireString = jwsInput.getWireString();
            log.tracef("\taccess_token: %s", wireString.substring(0, wireString.lastIndexOf(".")) + ".signature");


        } catch (JWSInputException e) {
            System.out.println("Failed to parse access_toke");

            log.errorf(e, "Failed to parse access_token: %s", tokenString);
        }
//		}
        try {
            token = AdapterTokenVerifier.verifyToken(tokenString, deployment);

        } catch (VerificationException e) {
            log.debug("Failed to verify token");
            challenge = challengeResponse(exchange, OIDCAuthenticationError.Reason.INVALID_TOKEN, "invalid_token", e.getMessage());
            return AuthOutcome.FAILED;
        }
        if (token.getIssuedAt() < deployment.getNotBefore()) {
            log.debug("Stale token");
            challenge = challengeResponse(exchange, OIDCAuthenticationError.Reason.STALE_TOKEN, "invalid_token", "Stale token");
            System.out.println("token.getIssuedAt() < deployment.getNotBefore() ");

            return AuthOutcome.FAILED;
        }
        boolean verifyCaller = false;
        if (deployment.isUseResourceRoleMappings()) {
            verifyCaller = token.isVerifyCaller(deployment.getResourceName());
        } else {
            verifyCaller = token.isVerifyCaller();
        }
        surrogate = null;
        if (verifyCaller) {

            if (token.getTrustedCertificates() == null || token.getTrustedCertificates().isEmpty()) {
                log.warn("No trusted certificates in token");
                challenge = clientCertChallenge();

                return AuthOutcome.FAILED;
            }

            // for now, we just make sure Undertow did two-way SSL
            // assume JBoss Web verifies the client cert
            X509Certificate[] chain = new X509Certificate[0];
            try {

                chain = (X509Certificate[]) exchange
                        .getAttribute("javax.servlet.request.X509Certificate");

//				chain = exchange.getCertificateChain();
            } catch (Exception ignore) {

            }
            if (chain == null || chain.length == 0) {

                log.warn("No certificates provided by undertow to verify the caller");
                challenge = clientCertChallenge();
                return AuthOutcome.FAILED;
            }
            surrogate = chain[0].getSubjectDN().getName();
        }
        log.debug("successful authorized");
        return AuthOutcome.AUTHENTICATED;
    }


    protected AuthChallenge clientCertChallenge() {
        return new AuthChallenge() {
            @Override
            public int getResponseCode() {
                return 0;
            }

            @Override
            public boolean challenge(HttpFacade exchange) {
                // do the same thing as client cert auth
                return false;
            }
        };
    }


    protected AuthChallenge challengeResponse(HttpServletRequest facade, final OIDCAuthenticationError.Reason reason, final String error, final String description) {
        StringBuilder header = new StringBuilder("Bearer realm=\"");
        header.append(deployment.getRealm()).append("\"");
        if (error != null) {
            header.append(", error=\"").append(error).append("\"");
        }
        if (description != null) {
            header.append(", error_description=\"").append(description).append("\"");
        }
        final String challenge = header.toString();
        return new AuthChallenge() {
            @Override
            public int getResponseCode() {
                return 401;
            }

            @Override
            public boolean challenge(HttpFacade facade) {
                if (deployment.getPolicyEnforcer() != null) {
                    deployment.getPolicyEnforcer().enforce(OIDCHttpFacade.class.cast(facade));
                    return true;
                }
                OIDCAuthenticationError error = new OIDCAuthenticationError(reason, description);
                facade.getRequest().setError(error);
                facade.getResponse().addHeader("WWW-Authenticate", challenge);
                if (deployment.isDelegateBearerErrorResponseSending()) {
                    facade.getResponse().setStatus(401);
                } else {
                    facade.getResponse().sendError(401);
                }
                return true;
            }
        };
    }

}
