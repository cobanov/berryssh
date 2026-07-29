package berryssh.device;

import java.io.IOException;

import javax.microedition.rms.RecordEnumeration;
import javax.microedition.rms.RecordStore;
import javax.microedition.rms.RecordStoreException;

import berryssh.protocol.KnownHosts;
import berryssh.protocol.SshException;
import berryssh.protocol.WireReader;
import berryssh.protocol.WireWriter;

/**
 * Host key storage in RMS, the record store every MIDP implementation has.
 *
 * RMS is MIDP rather than RIM, so it needs no signature — which is the whole
 * reason it is usable here. Records are app-private, so a key written by this
 * MIDlet cannot be read or replaced by another one.
 *
 * This is the one class in the protocol path that cannot run on the host, which
 * is why the decision it serves lives in {@link KnownHosts} instead of in here.
 * What is left is lookup and append, and it still compiles against the CLDC and
 * MIDP bootclasspath like everything else.
 *
 * Written for -source 1.3: no generics, no enhanced for, no StringBuilder.
 */
public final class RecordStoreHostKeys implements KnownHosts.Store {

    private static final String STORE_NAME = "berryssh_hostkeys";

    public byte[] lookup(String host, int port) throws IOException {
        RecordStore store = open();
        try {
            RecordEnumeration records = store.enumerateRecords(null, null, false);
            String wanted = key(host, port);
            while (records.hasNextElement()) {
                byte[] record = records.nextRecord();
                WireReader r = new WireReader(record);
                if (wanted.equals(r.readAsciiString())) {
                    return r.readString();
                }
            }
            return null;
        } catch (RecordStoreException e) {
            throw new SshException("could not read the host key store: " + e.getMessage());
        } finally {
            close(store);
        }
    }

    public void store(String host, int port, byte[] blob) throws IOException {
        RecordStore store = open();
        try {
            // Any existing record for this host goes first. A store that grew a
            // second entry would make which key is trusted depend on
            // enumeration order.
            RecordEnumeration records = store.enumerateRecords(null, null, false);
            String wanted = key(host, port);
            while (records.hasNextElement()) {
                int id = records.nextRecordId();
                WireReader r = new WireReader(store.getRecord(id));
                if (wanted.equals(r.readAsciiString())) {
                    store.deleteRecord(id);
                }
            }

            WireWriter w = new WireWriter(128);
            w.writeAsciiString(wanted);
            w.writeString(blob);
            byte[] record = w.toByteArray();
            store.addRecord(record, 0, record.length);
        } catch (RecordStoreException e) {
            throw new SshException("could not write the host key store: " + e.getMessage());
        } finally {
            close(store);
        }
    }

    /** Removes a host, so a genuinely rebuilt server can be accepted afresh. */
    public void forget(String host, int port) throws IOException {
        RecordStore store = open();
        try {
            RecordEnumeration records = store.enumerateRecords(null, null, false);
            String wanted = key(host, port);
            while (records.hasNextElement()) {
                int id = records.nextRecordId();
                WireReader r = new WireReader(store.getRecord(id));
                if (wanted.equals(r.readAsciiString())) {
                    store.deleteRecord(id);
                }
            }
        } catch (RecordStoreException e) {
            throw new SshException("could not update the host key store: " + e.getMessage());
        } finally {
            close(store);
        }
    }

    /**
     * The port is part of the identity: two servers on one address are two
     * different hosts, and OpenSSH's known_hosts treats them that way too.
     */
    private static String key(String host, int port) {
        return host + ":" + port;
    }

    private static RecordStore open() throws IOException {
        try {
            return RecordStore.openRecordStore(STORE_NAME, true);
        } catch (RecordStoreException e) {
            throw new SshException("could not open the host key store: " + e.getMessage());
        }
    }

    private static void close(RecordStore store) {
        try {
            store.closeRecordStore();
        } catch (RecordStoreException e) {
            // Nothing useful to do: the records are already written, and
            // throwing here would replace a real error with a cosmetic one.
        }
    }
}
