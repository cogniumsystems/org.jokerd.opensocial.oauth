package org.jokerd.opensocial.oauth;

import java.util.Map;
import java.util.Scanner;

/**
 * @author kotelnikov
 */
public class OAuthTools {

    public static void main(String[] args) throws Exception {
        String baseDir = "../../org.jokerd/workdir";
        Map<String, String> map = OAuthHelper.getParams(args);
        String network = map.get("network");
        if (network == null) {
            map.put("scope", "read_stream,email");
            network = "facebook.com";
        }

        OAuthHelper oauthHelper = FileBasedOAuthInfoStore.getOAuthHelper(
            baseDir + "/access/" + network + "-oauth.json",
            baseDir + "/access/" + network + "-oauth.json-template",
            map);

        String networkName = oauthHelper.getNetworkName();
        Scanner in = new Scanner(System.in);
        System.out.println("=== " + networkName + "'s OAuth Workflow ===");
        System.out.println();
        System.out.println("Start authentication process...");
        String url = oauthHelper.getAuthenticationRequestUrl();
        String requestToken = oauthHelper.getAuthenticationRequestToken();
        System.out.println("Authentication Token: " + requestToken + "");
        System.out
            .println("Please authorize the application access on this address:");
        System.out.println(url);
        System.out.println("And paste the verifier here");
        System.out.print(">>");
        String str = in.nextLine();
        System.out.println();
        System.out.println("Get the Access Info...");
        Map<String, String> response = OAuthHelper.getParams(str);
        String verifierCode = response.get("code");
        if (verifierCode == null) {
            verifierCode = response.get("oauth_verifier");
        }
        if (verifierCode == null) {
            verifierCode = str;
        }
        oauthHelper.setAuthenticationResponse(verifierCode);
        System.out.println("Got the Access Info:");
        String accessToken = oauthHelper.getAccessToken();
        String accessSecret = oauthHelper.getAccessSecret();
        System.out.println(" * token:  " + accessToken);
        System.out.println(" * secret: " + accessSecret);
        System.out.println();
    }

}
