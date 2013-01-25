/**
 * 
 */
package org.jokerd.opensocial.oauth;

import java.io.File;
import java.io.IOException;
import java.io.UnsupportedEncodingException;
import java.net.URLDecoder;
import java.util.ArrayList;
import java.util.Collection;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.logging.Level;
import java.util.logging.Logger;

import org.scribe.builder.ServiceBuilder;
import org.scribe.builder.api.Api;
import org.scribe.model.OAuthRequest;
import org.scribe.model.Response;
import org.scribe.model.Token;
import org.scribe.model.Verb;
import org.scribe.model.Verifier;
import org.scribe.oauth.OAuthService;
import org.ubimix.commons.json.JsonObject;

/**
 * @author kotelnikov
 */
public class OAuthHelper {

    public interface IOAuthInfoStore {

        JsonObject getOAuthInfo();

        void setOAuthInfo(JsonObject info);
    }

    private static Logger log = Logger.getLogger(OAuthHelper.class.getName());

    public static Map<String, String> getMap(String... args) {
        Map<String, String> result = new HashMap<String, String>();
        for (int i = 0; i < args.length;) {
            String key = args[i++];
            String value = i < args.length ? args[i++] : null;
            result.put(key, value);
        }
        return result;
    }

    public static OAuthHelper getOAuthHelper(
        File authInfo,
        Map<String, String> map) throws IOException {
        IOAuthInfoStore store = new FileBasedOAuthInfoStore(authInfo);
        return new OAuthHelper(store, map);
    }

    public static OAuthHelper getOAuthHelper(File authInfo, String... args)
        throws IOException {
        Map<String, String> map = getMap(args);
        return getOAuthHelper(authInfo, map);
    }

    public static Map<String, String> getParams(String... args)
        throws UnsupportedEncodingException {
        if (args.length == 1) {
            String str = args[0];
            int idx = str.indexOf("?");
            if (idx >= 0) {
                str = str.substring(idx + 1);
            }
            str = str.replaceAll("^[&]+", "").replaceAll("[&]$", "");
            String[] array = str.split("[&]");
            List<String> list = new ArrayList<String>();
            for (String pair : array) {
                idx = pair.indexOf("=");
                String key = pair;
                String value = "";
                if (idx > 0) {
                    key = pair.substring(0, idx);
                    value = pair.substring(idx + 1);
                }
                value = URLDecoder.decode(value, "UTF-8");
                list.add(key);
                list.add(value);
            }
            args = list.toArray(new String[list.size()]);
        }
        return getMap(args);
    }

    private JsonObject fAuthInfo;

    private OAuthService fService;

    private IOAuthInfoStore fStore;

    public OAuthHelper(IOAuthInfoStore store, Map<String, String> params)
        throws IOException {
        try {
            fStore = store;
            fAuthInfo = fStore.getOAuthInfo();
            String apiKey = fAuthInfo.getString("consumerKey");
            String apiSecret = fAuthInfo.getString("consumerSecret");
            String apiClassName = getApiClassName();
            @SuppressWarnings("unchecked")
            Class<? extends Api> apiType = (Class<? extends Api>) Class
                .forName(apiClassName);
            ServiceBuilder builder = new ServiceBuilder()
                .provider(apiType)
                .apiKey(apiKey)
                .apiSecret(apiSecret);
            String scope = getParam(fAuthInfo, params, "scope");
            if (scope != null) {
                builder.scope(scope);
            }
            String callbackUri = getParam(fAuthInfo, params, "callbackUri");
            if (callbackUri != null && !"".equals(callbackUri)) {
                builder.callback(callbackUri);
            }
            fService = builder.build();
        } catch (Throwable t) {
            throw handleError("Can not create a OAuth server", t);
        }
    }

    public String call(
        String resourceURL,
        Collection<? extends Map.Entry<?, ?>> parameters) throws IOException {
        try {
            Token accessToken = getToken("access");
            OAuthRequest request = new OAuthRequest(Verb.GET, resourceURL);
            fService.signRequest(accessToken, request);
            Response response = request.send();
            return response.getBody();
        } catch (Exception t) {
            throw handleError("Can not retrieve the requested resource", t);
        }
    }

    public String getAccessSecret() {
        Token token = getToken("access");
        return token != null ? token.getSecret() : null;
    }

    public String getAccessToken() {
        Token token = getToken("access");
        return token != null ? token.getToken() : null;
    }

    private String getApiClassName() {
        String type = fAuthInfo.getString("type");
        if (type == null) {
            type = getNetworkName();
        }
        if (type == null) {
            return null;
        }
        String className = "org.scribe.builder.api."
            + Character.toUpperCase(type.charAt(0))
            + type.substring(1)
            + "Api";
        return className;
    }

    public String getAuthenticationRequestToken() {
        return fAuthInfo.getString("requestToken");
    }

    public String getAuthenticationRequestUrl() {
        Token requestToken = null;
        try {
            requestToken = fService.getRequestToken();
        } catch (UnsupportedOperationException e) {
            // Just ignore it.
        }
        String authUrl = fService.getAuthorizationUrl(requestToken);
        setToken("request", requestToken);
        removeToken("access");
        fStore.setOAuthInfo(fAuthInfo);
        return authUrl;
    }

    public String getNetworkName() {
        return fAuthInfo.getString("name");
    }

    private String getParam(
        JsonObject authInfo,
        Map<String, String> params,
        String key) {
        String result = fAuthInfo.getString(key);
        if (result == null) {
            result = params.get(key);
        }
        return result;
    }

    private Token getToken(String prefix) {
        String token = fAuthInfo.getString(prefix + "Token");
        String secret = fAuthInfo.getString(prefix + "Secret");
        if (token == null) {
            return null;
        }
        Token result = new Token(token, secret);
        return result;
    }

    private IOException handleError(String msg, Throwable t) {
        log.log(Level.FINE, msg, t);
        return new IOException(t);
    }

    public boolean hasAccessToken() {
        String accessToken = fAuthInfo.getString("accessToken");
        return accessToken != null;
    }

    private void removeToken(String prefix) {
        setToken(prefix, null);
    }

    public void setAuthenticationResponse(String verifierStr) {
        Verifier verifier = new Verifier(verifierStr);
        Token requestToken = getToken("request");
        Token accessToken = fService.getAccessToken(requestToken, verifier);
        if (accessToken != null) {
            setToken("access", accessToken);
            removeToken("request");
            fStore.setOAuthInfo(fAuthInfo);
        }
    }

    private void setToken(String prefix, Token token) {
        if (token != null) {
            fAuthInfo.setValue(prefix + "Token", token.getToken());
            fAuthInfo.setValue(prefix + "Secret", token.getSecret());
        } else {
            fAuthInfo.removeValue(prefix + "Token");
            fAuthInfo.removeValue(prefix + "Secret");
        }
    }

}
