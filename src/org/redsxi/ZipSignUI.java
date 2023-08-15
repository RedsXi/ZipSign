package org.redsxi;

import javax.swing.*;
import javax.swing.filechooser.FileFilter;
import java.io.*;

public class ZipSignUI implements Serializable {
    public static final long serialVersionUID = 1145141919810L;
    private JFrame frame;
    private JPanel mainPanel;
    private JTextField zipPath;
    private JButton selectFileButton;
    private JButton selectPublicKeyButton;
    private JTextField pubKeyPath;
    private JTextField prvKeyPath;

    File zipFile;
    File priKey;
    File pubKey;

    public void show() {
        frame = new JFrame("ZipSign");
        frame.setContentPane(mainPanel);
        frame.setDefaultCloseOperation(JFrame.EXIT_ON_CLOSE);
        frame.pack();
        frame.setVisible(true);
    }

    private JButton selectPrivateKeyButton;
    private JButton createKeyPairButton;
    private JTextField authorField;
    private JButton signZipButton;
    private JButton checkSignButton;

    public ZipSignUI() {
        selectPublicKeyButton.addActionListener(e -> {
            JFileChooser chooser = new JFileChooser();
            chooser.setFileSelectionMode(JFileChooser.FILES_ONLY);
            chooser.setFileFilter(new PublicKeyFileFilter());
            if(chooser.showOpenDialog(frame) == JFileChooser.APPROVE_OPTION) {
                pubKey = chooser.getSelectedFile();
                pubKeyPath.setText(pubKey.getAbsolutePath());
                checkButtons();
            }
        });
        selectPrivateKeyButton.addActionListener(e -> {
            JFileChooser chooser = new JFileChooser();
            chooser.setFileSelectionMode(JFileChooser.FILES_ONLY);
            chooser.setFileFilter(new PrivateKeyFileFilter());
            if(chooser.showOpenDialog(frame) == JFileChooser.APPROVE_OPTION) {
                priKey = chooser.getSelectedFile();
                prvKeyPath.setText(priKey.getAbsolutePath());
                checkButtons();
            }
        });
        createKeyPairButton.addActionListener(e -> {
            byte[][] pair = RSAUtil.generateRSAKeypair();
            byte[] publicKey = pair[0];
            byte[] privateKey = pair[1];
            JFileChooser chooser = new JFileChooser();
            chooser.setFileSelectionMode(JFileChooser.FILES_ONLY);
            chooser.setFileFilter(new PublicKeyFileFilter());
            if(chooser.showSaveDialog(frame) == JFileChooser.APPROVE_OPTION) {
                File pub = chooser.getSelectedFile();
                if(!pub.getName().toLowerCase().endsWith(".pub-key")) pub = new File(pub.getAbsolutePath() + ".pub-key");
                if(pub.exists() || pub.isDirectory()) pub.delete();
                try {
                    pub.createNewFile();
                    FileOutputStream fos = new FileOutputStream(pub);
                    fos.write(publicKey);
                    fos.close();
                } catch (IOException ex) {
                    throw new RuntimeException(ex);
                }
            }

            JFileChooser chooser2 = new JFileChooser();
            chooser2.setFileSelectionMode(JFileChooser.FILES_ONLY);
            chooser2.setFileFilter(new PrivateKeyFileFilter());
            if(chooser2.showSaveDialog(frame) == JFileChooser.APPROVE_OPTION) {
                File pri = chooser2.getSelectedFile();

                if(pri.exists() || pri.isDirectory()) pri.delete();
                try {
                    if(!pri.getName().toLowerCase().endsWith(".prv-key")) pri = new File(pri.getAbsolutePath() + ".prv-key");                    pri.createNewFile();
                    FileOutputStream fos = new FileOutputStream(pri);
                    fos.write(privateKey);
                    fos.close();
                } catch (IOException ex) {
                    throw new RuntimeException(ex);
                }
            }

            JOptionPane.showMessageDialog(frame, "Key pair generated successfully", "Info", JOptionPane.INFORMATION_MESSAGE);
        });
        selectFileButton.addActionListener(e -> {
            JFileChooser chooser = new JFileChooser();
            chooser.setFileSelectionMode(JFileChooser.FILES_ONLY);
            chooser.setFileFilter(new ZipFileFilter());
            if(chooser.showOpenDialog(frame) == JFileChooser.APPROVE_OPTION) {
                zipFile = chooser.getSelectedFile();
                zipPath.setText(zipFile.getAbsolutePath());
                checkButtons();
            }
        });
        checkSignButton.addActionListener(e -> {
            ZipSignUtil.checkZipSign(zipFile, true, frame);
            JOptionPane.showMessageDialog(frame, "Check completed.", "Info", JOptionPane.INFORMATION_MESSAGE);
        });
        signZipButton.addActionListener(e -> {
            try (FileInputStream pub = new FileInputStream(pubKey);FileInputStream pri = new FileInputStream(priKey)){
                byte[] publicKey = pub.readAllBytes();
                byte[] privateKey = pri.readAllBytes();
                ZipSignUtil.signZip(zipFile, authorField.getText(), privateKey, publicKey);
            } catch (IOException ex) {
                throw new RuntimeException(ex);
            }
        });
    }

    private void checkButtons() {
        checkSignButton.setEnabled(zipFile != null);
        signZipButton.setEnabled(zipFile != null && pubKey != null && priKey != null);
    }

    private static class ZipFileFilter extends FileFilter {
        public boolean accept(File f) {
            return f.getName().toLowerCase().endsWith(".zip") || f.isDirectory();
        }

        public String getDescription() {
            return "Zip File(*.zip)";
        }
    }

    private static class PublicKeyFileFilter extends FileFilter {
        public boolean accept(File f) {
            return f.getName().toLowerCase().endsWith(".pub-key") || f.isDirectory();
        }

        public String getDescription() {
            return "Public Key file(*.pub-key)";
        }
    }

    private static class PrivateKeyFileFilter extends FileFilter {
        public boolean accept(File f) {
            return f.getName().toLowerCase().endsWith(".prv-key") || f.isDirectory();
        }

        public String getDescription() {
            return "Private Key file(*.prv-key)";
        }
    }
}
