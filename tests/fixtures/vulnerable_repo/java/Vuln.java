// Intentionally vulnerable Java fixture for Suzaku Compass tests.
// DO NOT use this code. It exists only as scanner bait.

import java.io.ObjectInputStream;
import java.io.FileInputStream;
import javax.naming.Context;
import javax.xml.parsers.DocumentBuilderFactory;
import javax.xml.parsers.DocumentBuilder;

public class Vuln {
    public static void unsafeDeserialize(String path) throws Exception {
        ObjectInputStream ois = new ObjectInputStream(new FileInputStream(path));
        Object o = ois.readObject();
    }

    public static void unsafeJndi(Context ctx, String name) throws Exception {
        ctx.lookup(name);
    }

    public static void unsafeExec(String cmd) throws Exception {
        Runtime.getRuntime().exec(cmd);
    }

    public static void unsafeXml(String xml) throws Exception {
        DocumentBuilderFactory factory = DocumentBuilderFactory.newInstance();
        DocumentBuilder builder = factory.newDocumentBuilder();
    }
}
