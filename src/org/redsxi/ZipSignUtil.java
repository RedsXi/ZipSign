package org.redsxi;

import com.google.gson.Gson;
import org.jetbrains.annotations.Contract;
import org.redsxi.data.ZipSignInfo;

import javax.swing.*;
import java.awt.*;
import java.io.*;
import java.nio.charset.Charset;
import java.security.*;
import java.util.Base64;
import java.util.zip.ZipEntry;
import java.util.zip.ZipFile;
import java.util.zip.ZipInputStream;
import java.util.zip.ZipOutputStream;

import static javax.swing.JOptionPane.ERROR_MESSAGE;
import static javax.swing.JOptionPane.WARNING_MESSAGE;

@SuppressWarnings("ALL")
public class ZipSignUtil {

    private static final int BUFFER_SIZE = 1024;
    private static final String ZIP_SIGN_META_NAME = "__zip_sign.meta";

    /**
     * Sign the zip file.
     * @param zipFile Source Zip file
     * @param author Zip file author
     * @param privateKey RSA private key
     * @param publicKey RSA public key
     * @throws IOException Don't ask me why, see stacktrace please
     */
    public static boolean signZip(File zipFile, String author, byte[] privateKey, byte[] publicKey) throws IOException {
        //666
        File newZipFile = new File(zipFile.getParent() + File.separator + "signed_" + zipFile.getName());
        newZipFile.createNewFile();
        ZipFile zipFileObj = new ZipFile(zipFile, Charset.forName("GBK"));
        if(zipFileObj.getEntry(ZIP_SIGN_META_NAME) != null) return false;
        ZipInputStream zis = new ZipInputStream(new FileInputStream(zipFile));
        ZipOutputStream zos = new ZipOutputStream(new FileOutputStream(newZipFile));
        String authorSign = sign(toInputStream(author.getBytes()), privateKey);
        String pKeyStr = encodeBase64(publicKey);
        ZipSignInfo info = new ZipSignInfo(author, authorSign, pKeyStr);
        ZipEntry entry;
        while((entry = zis.getNextEntry()) != null) {
            String filePath = entry.getName();
            zos.putNextEntry(entry);
            if(!(entry.getName().equals(ZIP_SIGN_META_NAME) || entry.isDirectory())) {
                info.add(ZipSignInfo.FileSignature.file(entry.getName(), inputStreamToOutputStreamAndSign(zis, zos, RSAUtil.getRSAPrivateKey(privateKey))));
            } else {
                inputStreamToOutputStream(zis, zos);
            }
            zos.closeEntry();
        }

        entry = new ZipEntry(ZIP_SIGN_META_NAME);
        Gson gson = new Gson();
        byte[] zipSignMetaData = gson.toJson(info).getBytes();
        zos.putNextEntry(entry);
        inputStreamToOutputStream(toInputStream(zipSignMetaData), zos);
        zos.closeEntry();
        zis.close();
        zos.close();
        zipFileObj.close();
        return true;
    }

    /**
     * Check Zip file's signature
     * @param zipFile Input Zip file
     * @param showAsDialog See {@return}
     * @return When <code>showDialog = true</code>, always return true. Otherwise, the results of validation are returned.
     */
    public static boolean checkZipSign(File zipFile, boolean showAsDialog, Component parent) {
        //if(showAsDialog && parent == null) return false;
        if(!zipFile.exists()) {
            return showDialogOrReturnFalse("Zip file not found", "Error", ERROR_MESSAGE, showAsDialog, parent);
        }
        if(zipFile.isDirectory()) {
            return showDialogOrReturnFalse("Target path is a directory", "Error", ERROR_MESSAGE, showAsDialog, parent);
        }
        try (ZipFile file = new ZipFile(zipFile, Charset.forName("GBK"))) {
            ZipEntry metaEntry = file.getEntry(ZIP_SIGN_META_NAME);
            if(metaEntry == null) {
                showDialogOrReturnFalse("Zip file not signed", "Warning", WARNING_MESSAGE, showAsDialog, parent);
                return true;
            }
            InputStreamReader reader = new InputStreamReader(file.getInputStream(metaEntry));
            Gson gson = new Gson();
            ZipSignInfo info = gson.fromJson(reader, ZipSignInfo.class);
            byte[] providedPublicKey = decodeBase64(info.getPublicKey());
            if(signIsInvalid(toInputStream(info.getAuthor().getBytes()), info.getAuthorSignature(), providedPublicKey)) {
                return showDialogOrReturnFalse("Author check failed. Author may not " + info.getAuthor(), "Error", ERROR_MESSAGE, showAsDialog, parent);
            }

            ZipInputStream zis = new ZipInputStream(new FileInputStream(zipFile), Charset.forName("GBK"));
            ZipEntry entry;

            while((entry = zis.getNextEntry()) != null) {
                if(entry.isDirectory() || entry.getName().equals(ZIP_SIGN_META_NAME)) continue;
                ZipSignInfo.FileSignature signature = info.getFileSignature(entry.getName());
                if(signIsInvalid(zis, signature.getSignature(), providedPublicKey)) {
                    zis.closeEntry();
                    return showDialogOrReturnFalse("Zip file sign check failed. Some files were changed or Zip file's author isn't " + info.getAuthor(), "Error", ERROR_MESSAGE, showAsDialog, parent);
                }
            }
            zis.close();
            file.close();
            return true;
        } catch (Exception e) {
            throw new RuntimeException(e);
        }
    }

    private static String sign(InputStream content, byte[] privateKey) {
        PrivateKey key = RSAUtil.getRSAPrivateKey(privateKey);
        try {
            Signature signature = Signature.getInstance("SHA256WithRSA");
            signature.initSign(key);
            byte[] buffer = new byte[BUFFER_SIZE];
            while(true) {
                int length = content.read(buffer);
                if(length == -1) break;
                signature.update(buffer, 0, length);
            }
            return encodeBase64(signature.sign());
        } catch (NoSuchAlgorithmException | InvalidKeyException | IOException | SignatureException e) {
            throw new RuntimeException(e);
        }
    }

    private static boolean verifySign(InputStream content, String signatureStr, byte[] publicKey) {
        PublicKey key = RSAUtil.getRSAPublicKey(publicKey);
        try {
            Signature signature = Signature.getInstance("SHA256WithRSA");
            signature.initVerify(key);
            byte[] buffer = new byte[BUFFER_SIZE];
            while(true) {
                int length = content.read(buffer);
                if(length == -1) break;
                signature.update(buffer, 0, length);
            }
            return signature.verify(decodeBase64(signatureStr));
        } catch (NoSuchAlgorithmException | InvalidKeyException | IOException | SignatureException e) {
            throw new RuntimeException(e);
        }
    }

    private static boolean signIsInvalid(InputStream content, String signatureStr, byte[] publicKey) {
        return !verifySign(content, signatureStr, publicKey);
    }
    private static ByteArrayInputStream toInputStream(byte[] bytes) {
        return new ByteArrayInputStream(bytes);
    }

    private static void inputStreamToOutputStream(InputStream stream, OutputStream outputStream) throws IOException {
        byte[] buffer = new byte[BUFFER_SIZE];
        while(true) {
            int readByte = stream.read(buffer);
            outputStream.write(buffer, 0, readByte);
            if(readByte < buffer.length) break;
        }
    }

    @Contract("_,_,_,false,_ -> false;null,_,_,true,_ -> fail;!null,_,_,true,_ -> true")
    private static boolean showDialogOrReturnFalse(String message, String title, int messageType, boolean showDialog, Component parent) {
        if(showDialog) JOptionPane.showMessageDialog(parent, message, title, messageType);
        return showDialog;
    }

    private static String encodeBase64(byte[] data) {
        return Base64
                .getEncoder()
                .encodeToString(data)
                .replace("+", ",")
                .replace("/", "-")
                .replace("=", ".");
    }

    private static byte[] decodeBase64(String base64) {
        return Base64
                .getDecoder()
                .decode(
                        base64
                                .replace(",", "+")
                                .replace("-", "/")
                                .replace(".", "=")
                );
    }

    private static String inputStreamToOutputStreamAndSign(InputStream is, OutputStream os, PrivateKey privateKey) {
        try {
            Signature signature = Signature.getInstance("SHA256WithRSA");
            signature.initSign(privateKey);
            byte[] buffer = new byte[BUFFER_SIZE];
            while(true) {
                int length = is.read(buffer);
                if(length == -1) break;
                os.write(buffer, 0, length);
                signature.update(buffer, 0, length);
            }
            return encodeBase64(signature.sign());
        } catch (NoSuchAlgorithmException | InvalidKeyException | IOException | SignatureException e) {
            throw new RuntimeException(e);
        }
    }
}
