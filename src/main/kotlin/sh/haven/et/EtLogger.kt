package sh.haven.et

/**
 * Logging interface for the ET transport library.
 * Implement this to bridge to your platform's logging (e.g. android.util.Log).
 */
interface EtLogger {
    fun d(tag: String, msg: String)
    fun e(tag: String, msg: String, throwable: Throwable? = null)
}

/** Default no-op logger. */
object NoOpEtLogger : EtLogger {
    override fun d(tag: String, msg: String) {}
    override fun e(tag: String, msg: String, throwable: Throwable?) {}
}

/** Logger that prints to stdout/stderr. */
object StdEtLogger : EtLogger {
    override fun d(tag: String, msg: String) { println("[$tag] $msg") }
    override fun e(tag: String, msg: String, throwable: Throwable?) {
        System.err.println("[$tag] ERROR: $msg")
        throwable?.printStackTrace(System.err)
    }
}
