package berryssh.device;

import java.io.IOException;

import javax.microedition.rms.RecordEnumeration;
import javax.microedition.rms.RecordStore;
import javax.microedition.rms.RecordStoreException;

import berryssh.protocol.SshException;

/**
 * Saved connections, in RMS.
 *
 * The same arrangement as {@link RecordStoreHostKeys}: RMS is MIDP rather than
 * RIM, so it needs no signature, and its records are private to this MIDlet.
 *
 * <b>Not encrypted.</b> A saved password is protected by the handset's own lock
 * and by nothing else. That is a real limit and the UI says so rather than
 * implying otherwise — CLDC has no key store to do better with, and inventing
 * an encryption scheme whose key would have to live beside the data would be
 * theatre.
 *
 * Written for -source 1.3: no generics, no enhanced for, no StringBuilder.
 */
public final class RecordStoreProfiles implements Profile.Store {

    private static final String STORE_NAME = "berryssh_connections";

    public Profile[] list() throws IOException {
        RecordStore store = open();
        try {
            RecordEnumeration records = store.enumerateRecords(null, null, false);
            Profile[] found = new Profile[store.getNumRecords()];
            int n = 0;
            while (records.hasNextElement()) {
                byte[] record = records.nextRecord();
                try {
                    found[n++] = Profile.decode(record);
                } catch (IOException e) {
                    // A record this version cannot read is skipped rather than
                    // fatal: one unreadable entry should not cost the others.
                    n--;
                }
            }
            Profile[] exact = new Profile[n];
            System.arraycopy(found, 0, exact, 0, n);
            return exact;
        } catch (RecordStoreException e) {
            throw new SshException("could not read saved connections: " + e.getMessage());
        } finally {
            close(store);
        }
    }

    /** Saves, replacing any profile of the same name. */
    public void save(Profile profile) throws IOException {
        RecordStore store = open();
        try {
            deleteMatching(store, profile.name());
            byte[] record = profile.encode();
            store.addRecord(record, 0, record.length);
        } catch (RecordStoreException e) {
            throw new SshException("could not save the connection: " + e.getMessage());
        } finally {
            close(store);
        }
    }

    public void delete(String name) throws IOException {
        RecordStore store = open();
        try {
            deleteMatching(store, name);
        } catch (RecordStoreException e) {
            throw new SshException("could not delete the connection: " + e.getMessage());
        } finally {
            close(store);
        }
    }

    private static void deleteMatching(RecordStore store, String name)
            throws RecordStoreException {
        RecordEnumeration records = store.enumerateRecords(null, null, false);
        while (records.hasNextElement()) {
            int id = records.nextRecordId();
            try {
                if (name.equals(Profile.decode(store.getRecord(id)).name())) {
                    store.deleteRecord(id);
                }
            } catch (IOException e) {
                // Unreadable, so not the one being replaced. Left alone.
            }
        }
    }

    private static RecordStore open() throws IOException {
        try {
            return RecordStore.openRecordStore(STORE_NAME, true);
        } catch (RecordStoreException e) {
            throw new SshException("could not open saved connections: " + e.getMessage());
        }
    }

    private static void close(RecordStore store) {
        try {
            store.closeRecordStore();
        } catch (RecordStoreException e) {
            // The records are already written; throwing here would replace a
            // real error with a cosmetic one.
        }
    }
}
