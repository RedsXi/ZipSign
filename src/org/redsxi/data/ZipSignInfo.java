package org.redsxi.data;

import com.google.gson.annotations.JsonAdapter;
import com.google.gson.annotations.SerializedName;
import org.redsxi.ZipSignUtil;

import java.util.ArrayList;
import java.util.List;

public class ZipSignInfo {
    private String author;
    @SerializedName("key")
    private String authorPublicKey;

    @SerializedName("authorSignature")
    private String authorSign;
    @SerializedName("files")
    private List<FileSignature> signatureList = new ArrayList<>();

    public ZipSignInfo(String author, String authorSign, String publicKey) {
        this.author = author;
        this.authorSign = authorSign;
        this.authorPublicKey = publicKey;
    }

    public void add(FileSignature s) {
        signatureList.add(s);
    }

    public List<FileSignature> getFiles() {
        return signatureList;
    }

    public static class FileSignature {
        @SerializedName("file")
        private String path;
        @SerializedName("signature")
        private String sha;

        public static FileSignature file(String path, String sign) {
            FileSignature signature = new FileSignature();
            signature.path = path;
            signature.sha = sign;
            return signature;
        }

        public String getPath() {
            return path;
        }

        public String getSignature() {
            return sha;
        }
    }

    public String getAuthor() {
        return author;
    }

    public String getPublicKey() {
        return authorPublicKey;
    }

    public String getAuthorSignature() {
        return authorSign;
    }

    public FileSignature getFileSignature(String name) {
        for(FileSignature fs : signatureList) {
            if (fs.getPath().equals(name)) return fs;
        }
        return FileSignature.file("", "");
    }
}
