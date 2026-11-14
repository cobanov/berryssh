package berryssh.device;

import javax.microedition.rms.RecordStore;
import javax.microedition.rms.RecordStoreException;

/**
 * Thirty-two bytes of the random pool, kept in RMS between runs.
 *
 * A handset has very little to make randomness from at the moment it starts,
 * and rather more once it has been used: every key press since has gone into
 * the pool. Carrying the pool across runs means a session's keys rest on all of
 * that rather than on a tenth of a second of clock jitter alone.
 *
 * Failure is silent in both directions, on purpose. The stored bytes are mixed
 * in and not counted, so a missing or unreadable record changes nothing about
 * when the pool is ready — it only means this run starts where a first run
 * would.
 *
 * Written for -source 1.3: no generics, no enhanced for, no StringBuilder.
 */
final class RecordStoreSeed {

    private static final String STORE_NAME = "berryssh_seed";

    private RecordStoreSeed() {
    }

    /** The bytes saved by the last run, or null. */
    static byte[] load() {
        RecordStore store = null;
        try {
            store = RecordStore.openRecordStore(STORE_NAME, true);
            return store.getNumRecords() == 0 ? null : store.getRecord(1);
        } catch (RecordStoreException e) {
            return null;
        } finally {
            close(store);
        }
    }

    static void save(byte[] seed) {
        RecordStore store = null;
        try {
            store = RecordStore.openRecordStore(STORE_NAME, true);
            if (store.getNumRecords() == 0) {
                store.addRecord(seed, 0, seed.length);
            } else {
                store.setRecord(1, seed, 0, seed.length);
            }
        } catch (RecordStoreException e) {
            // The next run starts cold, which is where every first run starts.
        } finally {
            close(store);
        }
    }

    private static void close(RecordStore store) {
        try {
            if (store != null) {
                store.closeRecordStore();
            }
        } catch (RecordStoreException e) {
            // Nothing useful to do.
        }
    }
}
