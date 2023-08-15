package org.redsxi;

import javax.swing.filechooser.FileFilter;
import java.io.File;

public abstract class IFileFilter extends FileFilter {
    public abstract String getExtension();

    public abstract String description();

    public String getDescription() {
        return description() + "(." + getExtension() + ")";
    }

    public boolean accept(File f) {
        return f.getName().toLowerCase().endsWith("." + getDescription());
    }
}
