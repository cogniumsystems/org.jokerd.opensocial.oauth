package org.jokerd.opensocial.oauth;

import java.io.File;
import java.io.FileInputStream;
import java.io.FileOutputStream;
import java.io.IOException;
import java.util.Map;
import java.util.logging.Level;
import java.util.logging.Logger;

import org.jokerd.opensocial.oauth.OAuthHelper.IOAuthInfoStore;
import org.ubimix.commons.io.IOUtil;
import org.ubimix.commons.json.JsonObject;

/**
 * @author kotelnikov
 */
public class FileBasedOAuthInfoStore implements IOAuthInfoStore {

    private final static Logger log = Logger
        .getLogger(FileBasedOAuthInfoStore.class.getName());

    public static File checkFile(String fileName, String templateName)
        throws IOException {
        File authFile = new File(fileName);
        File templateAuthInfof = new File(templateName);
        copyAuthInfo(authFile, templateAuthInfof);
        return authFile;
    }

    public static void copyAuthInfo(File authInfo, File templateAuthInfo)
        throws IOException {
        if (!authInfo.exists()) {
            FileInputStream input = new FileInputStream(templateAuthInfo);
            FileOutputStream out = new FileOutputStream(authInfo);
            IOUtil.copy(input, out);
        }
    }

    public static OAuthHelper getOAuthHelper(
        String infoFileName,
        String infoTemplateName,
        Map<String, String> map) throws IOException {
        File authInfo = checkFile(infoFileName, infoTemplateName);
        OAuthHelper oauthHelper = OAuthHelper.getOAuthHelper(authInfo, map);
        return oauthHelper;
    }

    private static void handleError(String msg, Throwable e) {
        log.log(Level.FINE, msg, e);
    }

    private static JsonObject readInfo(File file) {
        JsonObject result = null;
        try {
            String str = IOUtil.readString(file);
            result = JsonObject.FACTORY.newValue(str);
        } catch (IOException e) {
            handleError("Can not read a JSON file. File: " + file, e);
            result = new JsonObject();
        }
        return result;
    }

    private static void writeInfo(File file, JsonObject info) {
        try {
            IOUtil.writeString(file, info.toString());
        } catch (IOException e) {
            handleError("Can not write a JSON file. File: " + file, e);
        }
    }

    private final File fFile;

    private JsonObject fInfo;

    public FileBasedOAuthInfoStore(File file) {
        fFile = file;
    }

    @Override
    public JsonObject getOAuthInfo() {
        if (fInfo == null) {
            fInfo = readInfo(fFile);
        }
        return fInfo;
    }

    @Override
    public void setOAuthInfo(JsonObject info) {
        fInfo = info;
        writeInfo(fFile, fInfo);
    }

}