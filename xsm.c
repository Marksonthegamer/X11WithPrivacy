#define _GNU_SOURCE

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include <X11/X.h>
#include <X11/Xproto.h>
#include <X11/extensions/secur.h>

#include <scrnintstr.h>
#include <windowstr.h>
#include <misc.h>
#include <extnsionst.h>
#include <gcstruct.h>
#include <privates.h>
#include <registry.h>
#include <xace.h>
#include <xacestr.h>
#include <xf86.h>
#include <resource.h>
#include <inputstr.h>
#include <dixstruct.h>

#include <systemd/sd-journal.h>
#include <pthread.h>
#include <sys/inotify.h>
#include <unistd.h>
#include <time.h>
#include <dbus/dbus.h>


#define XORG_VERSION_CURRENT (((1) * 10000000) + ((19) * 100000) + ((2) * 1000) + 0)
#define SECURITY_AUDIT_LEVEL 4

#define POLICY_BUF_SIZE	1024
#define DEFAULT_POLICY_PATH "/etc/xsm/default.rules"

#define XSM_ALLOW	1
#define XSM_DISALLOW 0

#define XSM_SCREENSHOT	0
#define XSM_SCREENCAST	1
#define XSM_XRECORD		3
#define XSM_CLIPBOARD	4

#define LOG_ID "XSM-LOG"

#define LOG_SCREENSHOT	0
#define LOG_SCREENCAST	1
#define LOG_XRECORD		3
#define LOG_CLIPBOARD	4

#define LOG_SCREENSHOT_BODY	"Screenshot restricted for process "
#define LOG_SCREENCAST_BODY	"Screencast restricted for process "
#define LOG_XRECORD_BODY	"Xsession record or replay restricted for process "
#define LOG_CLIPBOARD_BODY	"Clipboard restricted. for process "
#define LOG_UNKNOWN_BODY	"Unknown action restricted for process "

#define NOTIFY_MSG_SCR	" attempts to capture your screen."
#define NOTIFY_MSG_CLP	" attempts to capture your clipboard."

#define INOTIFY_MAX_EVENTS	1024 /* Max. number of events to process at one go */
#define INOTIFY_LEN_NAME 	16 /* Assuming that the length of the filename won't exceed 16 bytes */
#define INOTIFY_EVENT_SIZE  ( sizeof (struct inotify_event) ) /*size of one event */
#define INOTIFY_BUF_LEN     ( INOTIFY_MAX_EVENTS * ( INOTIFY_EVENT_SIZE + INOTIFY_LEN_NAME )) /* buffer to store the data of events */

#define POLICY_DIR_PATH		"/etc/xsm/"
#define POLICY_SCRS_ATTR	"screenshot"
#define POLICY_SCRT_ATTR	"screencast"
#define POLICY_XRER_ATTR	"xrecord"
#define POLICY_CLIP_ATTR	"clipboard"

#define POLICY_ALLOW_STR	"allow"
#define POLICY_DISALLOW_STR	"disallow"

#define PID_SAVE_TIMEOUT	5

#define WHITELIST_SCREENSHOT   "/etc/xsm/whitelist_screenshot"
#define WHITELIST_SCREENCAST   "/etc/xsm/whitelist_screencast"
#define WHITELIST_XRECORD      "/etc/xsm/whitelist_xrecord"
#define WHITELIST_CLIPBOARD    "/etc/xsm/whitelist_clipboard"

#define BLACKLIST_SCREENSHOT   "/etc/xsm/blacklist_screenshot"
#define BLACKLIST_SCREENCAST   "/etc/xsm/blacklist_screencast"
#define BLACKLIST_XRECORD      "/etc/xsm/blacklist_xrecord"
#define BLACKLIST_CLIPBOARD    "/etc/xsm/blacklist_clipboard"

#define MAX_WHITELIST_ENTRIES   64

#define MAX_BLACKLIST_ENTRIES   64

#define MAX_CMDNAME_LEN         256

void write_journal_log(int priority, const char *logmsg, const char *custom_fields);
int parse_policy_value(const char *buf, long size, const char *key);


static MODULESETUPPROTO(XsmSetup);

Bool noXsmExtension = FALSE;

/* Extension stuff */
static int XsmErrorBase;   /* first Security error number */                                   
static int XsmEventBase;   /* first Security event number */


//CallbackListPtr ClientStateCallback;

/* This structure is expected to be returned by the initfunc */
// typedef struct {
//   const char *modname;        /* name of module, e.g. "foo" */
// 	 const char *vendor;         /* vendor specific string */
//	 CARD32 _modinfo1_;          /* constant MODINFOSTRING1/2 to find */
//	 CARD32 _modinfo2_;          /* infoarea with a binary editor or sign tool */
//	 CARD32 xf86version;         /* contains XF86_VERSION_CURRENT */
//	 CARD8 majorversion;         /* module-specific major version */
//	 CARD8 minorversion;         /* module-specific minor version */
//	 CARD16 patchlevel;          /* module-specific patch level */
//	 const char *abiclass;       /* ABI class that the module uses */
//	 CARD32 abiversion;          /* ABI version */
//	 const char *moduleclass;    /* module class description */
//	 CARD32 checksum[4];         /* contains a digital signature of the */
	 /* version info structure */
//} XF86ModuleVersionInfo;   


static XF86ModuleVersionInfo VersRec = { 
	"Xsm",
	"ultract@nsr.re.kr",	/* MODULEVENDORSTRING */
	MODINFOSTRING1,
	MODINFOSTRING2,
	XORG_VERSION_CURRENT,
	1, 0, 0,
	ABI_CLASS_EXTENSION,
	ABI_EXTENSION_VERSION,                                                                               
	MOD_CLASS_NONE,
	{0, 0, 0, 0}
};


/*
 * Access modes
 */

static const Mask XsmResourceMask = 
	DixGetAttrAccess | DixReceiveAccess | DixListPropAccess |
	DixGetPropAccess | DixListAccess;

static const Mask XsmWindowExtraMask = DixRemoveAccess;

static const Mask XsmRootWindowExtraMask =
    DixReceiveAccess | DixSendAccess | DixAddAccess | DixRemoveAccess;


_X_EXPORT XF86ModuleData xsmModuleData = { &VersRec, XsmSetup, NULL };

extern void XsmExtensionInit(void); 

static const ExtensionModule XsmExt[] = {
{ XsmExtensionInit, "Xsm", &noXsmExtension },
};


static _X_INLINE const char *
XsmLookupRequestName(ClientPtr client)
{
	return LookupRequestName(client->majorOp, client->minorOp);
}


static void
_X_ATTRIBUTE_PRINTF(1, 2)
XsmAudit(const char *format, ...)
{
	va_list args;

	if (auditTrailLevel < SECURITY_AUDIT_LEVEL)
		return;
	va_start(args, format);
	VAuditF(format, args);
	va_end(args);
}


void dbus_notify_signal(int idx, const char *process_name, const char *noti_msg)
{
    DBusError err;
    dbus_error_init(&err);

    // Connect to SYSTEM bus (accessible by X Server)
    DBusConnection* conn = dbus_bus_get(DBUS_BUS_SYSTEM, &err);
    if (conn == NULL || dbus_error_is_set(&err)) {
        write_journal_log(LOG_WARNING, "D-Bus System Bus connection failed", err.message);
        dbus_error_free(&err);
        return; // Don't exit! Just skip the signal.
    }

    // Define unique identifiers for your signal
    DBusMessage* dbus_msg = dbus_message_new_signal(
                            "/org/xsm/SecurityAlert",  // Path
                            "org.xsm.SecurityInterface", // Interface
                            "ViolationDetected");       // Signal Name
    if (NULL == dbus_msg) {
		dbus_connection_unref(conn);
        return;
    }

    dbus_message_append_args(dbus_msg, DBUS_TYPE_INT16, &idx, DBUS_TYPE_STRING, &process_name, DBUS_TYPE_STRING, &noti_msg, DBUS_TYPE_INVALID);

    dbus_uint32_t serial = 0;
    if (!dbus_connection_send(conn, dbus_msg, &serial)) {
        write_journal_log(LOG_WARNING, "Failed to send D-Bus signal", "");
    }

    dbus_connection_flush(conn);
    dbus_message_unref(dbus_msg);
	dbus_connection_unref(conn);
}



/* LOG_EMERG	0	system is unusable */
/* ALERT		1	action must be taken immediately */
/* LOG_CRIT		2	critical conditions */
/* LOG_ERR		3	error conditions */
/* LOG_WARNING	4	warning conditions */
/* LOG_NOTICE	5	normal but significant condition */
/* LOG_INFO		6	informational */
/* LOG_DEBUG	7	debug-level messages */

void write_journal_log(int priority, const char *logmsg, const char *custom_fields)
{
	/*
	openlog(LOG_ID, LOG_NDELAY, LOG_DAEMON);
	syslog(priority,logmsg);
	closelog();
	*/
	sd_journal_send("SYSLOG_IDENTIFIER=%s", LOG_ID,
					"PRIORITY=%d",priority,
					"MESSAGE=%s", logmsg,
					NULL);
}

/* 
 *	Default rule set -> disallow 
 */
static int screenshot_allow = XSM_ALLOW;
static int screencast_allow = XSM_ALLOW;
static int xrecord_allow = XSM_ALLOW;
static int clipboard_allow = XSM_ALLOW;

static char *whitelist_screenshot[MAX_WHITELIST_ENTRIES];
static char *whitelist_screencast[MAX_WHITELIST_ENTRIES];
static char *whitelist_xrecord[MAX_WHITELIST_ENTRIES];
static char *whitelist_clipboard[MAX_WHITELIST_ENTRIES];
static int   whitelist_screenshot_count = 0;
static int   whitelist_screencast_count = 0;
static int   whitelist_xrecord_count = 0;
static int   whitelist_clipboard_count = 0;

static char *blacklist_screenshot[MAX_BLACKLIST_ENTRIES];
static char *blacklist_screencast[MAX_BLACKLIST_ENTRIES];
static char *blacklist_xrecord[MAX_BLACKLIST_ENTRIES];
static char *blacklist_clipboard[MAX_BLACKLIST_ENTRIES];
static int   blacklist_screenshot_count = 0;
static int   blacklist_screencast_count = 0;
static int   blacklist_xrecord_count = 0;
static int   blacklist_clipboard_count = 0;

/* Generic free for any list */
static void free_list(char **list, int *count)
{
    for (int i = 0; i < *count; i++) {
        if (list[i]) free(list[i]);
        list[i] = NULL;
    }
    *count = 0;
}

/* Generic read function */
static void read_list(const char *filepath, char **list, int *count)
{
    FILE *fp;
    char line[MAX_CMDNAME_LEN];
    int c = 0;

    free_list(list, count);

    fp = fopen(filepath, "r");
    if (fp == NULL) {
        // Log only for default files if needed, but keep quiet for optional ones
        return;
    }

    while (fgets(line, sizeof(line), fp) && c < MAX_WHITELIST_ENTRIES) {
        char *p = line;
        while (*p && (*p == ' ' || *p == '\t')) p++;
        char *end = p + strlen(p) - 1;
        while (end > p && (*end == '\n' || *end == '\r' || *end == ' ' || *end == '\t')) {
            *end-- = '\0';
        }
        if (*p == '\0' || *p == '#') continue;

        list[c] = strdup(p);
        if (list[c]) c++;
    }
    fclose(fp);
    *count = c;

    char msg[128];
    snprintf(msg, sizeof(msg), "Loaded %d entries from %s", c, filepath);
    LogMessage(X_INFO, "%s\n", msg);
}

/* Per-action is_whitelisted */
static int is_whitelisted_screenshot(const char *cmd) {
    if (!cmd) return 0;
    for (int i = 0; i < whitelist_screenshot_count; i++)
        if (whitelist_screenshot[i] && strcmp(whitelist_screenshot[i], cmd) == 0) return 1;
    return 0;
}

static int is_whitelisted_screencast(const char *cmd) {
    if (!cmd) return 0;
    for (int i = 0; i < whitelist_screencast_count; i++)
        if (whitelist_screencast[i] && strcmp(whitelist_screencast[i], cmd) == 0) return 1;
    return 0;
}

static int is_whitelisted_xrecord(const char *cmd) {
    if (!cmd) return 0;
    for (int i = 0; i < whitelist_xrecord_count; i++)
        if (whitelist_xrecord[i] && strcmp(whitelist_xrecord[i], cmd) == 0) return 1;
    return 0;
}

static int is_whitelisted_clipboard(const char *cmd) {
    if (!cmd) return 0;
    for (int i = 0; i < whitelist_clipboard_count; i++)
        if (whitelist_clipboard[i] && strcmp(whitelist_clipboard[i], cmd) == 0) return 1;
    return 0;
}

/* Per-action is_blacklisted */
static int is_blacklisted_screenshot(const char *cmd) {
    if (!cmd) return 0;
    for (int i = 0; i < blacklist_screenshot_count; i++)
        if (blacklist_screenshot[i] && strcmp(blacklist_screenshot[i], cmd) == 0) return 1;
    return 0;
}

static int is_blacklisted_screencast(const char *cmd) {
    if (!cmd) return 0;
    for (int i = 0; i < blacklist_screencast_count; i++)
        if (blacklist_screencast[i] && strcmp(blacklist_screencast[i], cmd) == 0) return 1;
    return 0;
}

static int is_blacklisted_xrecord(const char *cmd) {
    if (!cmd) return 0;
    for (int i = 0; i < blacklist_xrecord_count; i++)
        if (blacklist_xrecord[i] && strcmp(blacklist_xrecord[i], cmd) == 0) return 1;
    return 0;
}

static int is_blacklisted_clipboard(const char *cmd) {
    if (!cmd) return 0;
    for (int i = 0; i < blacklist_clipboard_count; i++)
        if (blacklist_clipboard[i] && strcmp(blacklist_clipboard[i], cmd) == 0) return 1;
    return 0;
}


static int policy_check(int idx)
{
	if(idx == XSM_SCREENSHOT)
		return screenshot_allow;
	if(idx == XSM_SCREENCAST)
		return screencast_allow;
	if(idx == XSM_XRECORD)
		return xrecord_allow;
	if(idx == XSM_CLIPBOARD)
		return clipboard_allow;
}


/*
 *	Read policy
 *	- User policy has higher priority than the default policy.
 */
static void read_policy(void)
{
    FILE *fp;
    char *policy_buf = NULL;
    long file_size;
    int val;

    fp = fopen(DEFAULT_POLICY_PATH, "r");
    if (fp == NULL) {
        write_journal_log(LOG_WARNING, "Default-policy file: Not exist!!", "");
        write_journal_log(LOG_WARNING, "Screen-capture & clipboard: No restrict.", "");
        screenshot_allow = screencast_allow = xrecord_allow = clipboard_allow = XSM_ALLOW;
        return;
    }

    write_journal_log(LOG_NOTICE, "Default-policy file: Loaded", "");

    /* Get file size */
    fseek(fp, 0, SEEK_END);
    file_size = ftell(fp);
    rewind(fp);

    if (file_size <= 0) {
        fclose(fp);
        write_journal_log(LOG_WARNING, "Policy file is empty!", "");
        screenshot_allow = screencast_allow = xrecord_allow = clipboard_allow = XSM_ALLOW;
        return;
    }

    /* Allocate buffer */
    policy_buf = calloc(1, file_size + 1);
    if (!policy_buf) {
        fclose(fp);
        write_journal_log(LOG_ERR, "Memory allocation failed for policy", "");
        return;
    }

    /* Read file */
    if (fread(policy_buf, 1, file_size, fp) != (size_t)file_size) {
        free(policy_buf);
        fclose(fp);
        write_journal_log(LOG_WARNING, "Failed to read policy file", "");
        return;
    }
    fclose(fp);

    LogMessage(X_INFO, "Policy buffer loaded (size=%ld)\n", file_size);

    /* Parse Screenshot */
    val = parse_policy_value(policy_buf, file_size, POLICY_SCRS_ATTR);
    if (val != -1) screenshot_allow = val;
    else screenshot_allow = XSM_ALLOW; // Default
    
    /* Parse Screencast */
    val = parse_policy_value(policy_buf, file_size, POLICY_SCRT_ATTR);
    if (val != -1) screencast_allow = val;
    else screencast_allow = XSM_ALLOW;

    /* Parse Xrecord */
    val = parse_policy_value(policy_buf, file_size, POLICY_XRER_ATTR);
    if (val != -1) xrecord_allow = val;
    else xrecord_allow = XSM_ALLOW;

    /* Parse Clipboard */
    val = parse_policy_value(policy_buf, file_size, POLICY_CLIP_ATTR);
    if (val != -1) clipboard_allow = val;
    else clipboard_allow = XSM_ALLOW;

    free(policy_buf);
    
    LogMessage(X_INFO, "Policy applied successfully.\n");
}

int parse_policy_value(const char *buf, long size, const char *key) {
    const char *ptr = buf;
    long key_len = strlen(key);
    const char *end = buf + size;

    // Simple search for "key"
    while (ptr + key_len < end) {
        if (strncmp(ptr, key, key_len) == 0) {
            // Key found, look for colon and value
            const char *val_ptr = ptr + key_len;
            while (val_ptr < end && (*val_ptr == ' ' || *val_ptr == ':' || *val_ptr == '"' || *val_ptr == '\t')) {
                val_ptr++;
            }

            if (strncmp(val_ptr, "allow", 5) == 0) {
                return XSM_ALLOW;
            } else if (strncmp(val_ptr, "disallow", 8) == 0) {
                return XSM_DISALLOW;
            }
            return -1; // Key found but value invalid
        }
        ptr++;
    }
    return -1; // Key not found
}

int apply_policy(const char *pol_str, int idx, const char *name)
{
    if (!pol_str) {
        write_journal_log(LOG_WARNING, "Policy-file: %s rule not exist!", name);
        write_journal_log(LOG_WARNING, "%s: No restrict", name);
        return XSM_ALLOW;
    }

    if (!strcmp(pol_str, POLICY_ALLOW_STR)) {
        write_journal_log(LOG_NOTICE, "%s: Allow", name);
        return XSM_ALLOW;
    } else if (!strcmp(pol_str, POLICY_DISALLOW_STR)) {
        write_journal_log(LOG_NOTICE, "%s: Disallow", name);
        return XSM_DISALLOW;
    }

    write_journal_log(LOG_WARNING, "Policy-file: Invalid %s value!", name);
    return XSM_ALLOW;
}


/*
 * pthread for reading policy file
 *
 */

static pthread_t inotify_pthread;
static int inotify_fd; /* inotify file descriptor */

static void *inotify_policy_thread(void *param)
{
	int length, i = 0, wd;
	char buffer[INOTIFY_BUF_LEN];

	while(1)
	{
		i = 0;
		length = read(inotify_fd, buffer, INOTIFY_BUF_LEN );  
		
		if (length < 0)	/* If this occur then check file descriptor !! */
			LogMessage(X_INFO, "inotify_policy_thread : inotify policy read error!\n");

		while (i < length) {
			struct inotify_event *event = ( struct inotify_event * ) &buffer[i];
			
			//LogMessage(X_INFO, "inotify_policy_thread : event->len (%d)\n", event->len);
			if ( event->len ) {
				if (event->mask & IN_CREATE || event->mask & IN_MODIFY || event->mask & IN_DELETE ||
					event->mask & IN_MOVED_FROM || event->mask & IN_MOVED_TO) {
					
					if(event->name == NULL)
						continue;
					/*
					LogMessage(X_INFO, "inotify_policy_thread : event->mask & IN_CREATE "
										"event->name : %s \n", event->name); 
					*/

					/* "event->name" monitored file name via inotify */
					if(!strcmp(event->name, "user.rules") || !strcmp(event->name, "default.rules")||
					!strcmp(event->name, "whitelist"))
						read_policy();
						read_list(WHITELIST_SCREENSHOT, whitelist_screenshot, &whitelist_screenshot_count);
						read_list(WHITELIST_SCREENCAST, whitelist_screencast, &whitelist_screencast_count);
						read_list(WHITELIST_XRECORD,    whitelist_xrecord,    &whitelist_xrecord_count);
						read_list(WHITELIST_CLIPBOARD,  whitelist_clipboard,  &whitelist_clipboard_count);

						read_list(BLACKLIST_SCREENSHOT, blacklist_screenshot, &blacklist_screenshot_count);
						read_list(BLACKLIST_SCREENCAST, blacklist_screencast, &blacklist_screencast_count);
						read_list(BLACKLIST_XRECORD,    blacklist_xrecord,    &blacklist_xrecord_count);
						read_list(BLACKLIST_CLIPBOARD,  blacklist_clipboard,  &blacklist_clipboard_count);
						//printf( "The file %s was Created with WD %d\n", event->name, event->wd );
				}
				 
				i += INOTIFY_EVENT_SIZE + event->len;
			}
		}
	}
}

/*
 * Read policy file via inotify event
 *
 */
void inotify_policy(void)
{
	int length, i = 0, wd;
	char buffer[INOTIFY_BUF_LEN];
	int ret;

	/* Initialize Inotify */
	inotify_fd = inotify_init();
	if (inotify_fd < 0)
		LogMessage(X_INFO, "inotify_policy : Inotify policy load failed!\n");

	LogMessage(X_INFO, "inotify_policy : called\n");

	/* add watch to starting directory */
	wd = inotify_add_watch(inotify_fd, POLICY_DIR_PATH, 
				IN_CREATE | IN_MODIFY | IN_DELETE | IN_MOVED_FROM | IN_MOVED_TO); 

	if (wd == -1)
		LogMessage(X_INFO, "inotify_policy : Couldn't add watch to %s\n",POLICY_DIR_PATH);
	else
		LogMessage(X_INFO, "inotify_policy : Watching policy dir: %s\n", POLICY_DIR_PATH);

	/* Run thread */
	ret = pthread_create(&inotify_pthread, NULL, inotify_policy_thread, &inotify_fd);
	pthread_detach(inotify_pthread);
}


/* Initialize pid */
static int screenshot_pid = 0;
static int screencast_pid = 0;
static int xrecord_pid = 0;
static int clipboard_pid = 0;

/* Timer variables */
static int timer = 0;
struct timespec before, after;
long elapsed_secs = 0;

static void renew_pid()
{
	screenshot_pid = 0;
	screencast_pid = 0;
	xrecord_pid = 0;
	clipboard_pid = 0;
}

static void make_log(int idx, pid_t cmdpid, const char *cmdname)
{
	if(timer == 0)
	{
		clock_gettime(CLOCK_REALTIME, &before);
		timer = 1;
	}

	if(idx == LOG_SCREENSHOT && cmdpid != screenshot_pid)
	{
		screenshot_pid = cmdpid;
		char message[256];
		strcpy(message, cmdname);
		strcat(message, NOTIFY_MSG_SCR);
		dbus_notify_signal(idx, cmdname, message);
		strcpy(message, LOG_SCREENSHOT_BODY);
		strcat(message, cmdname);
		strcat(message, "\n");
		write_journal_log(LOG_CRIT, message, "");
		LogMessage(X_INFO, "%s", message);
	}
	else if(idx == LOG_SCREENCAST && cmdpid != screencast_pid)
	{
		screencast_pid = cmdpid;
		char message[256];
		strcpy(message, cmdname);
		strcat(message, NOTIFY_MSG_SCR);
		dbus_notify_signal(idx, cmdname, message);
		strcpy(message, LOG_SCREENCAST_BODY);
		strcat(message, cmdname);
		strcat(message, "\n");
		write_journal_log(LOG_CRIT, message, "");
		LogMessage(X_INFO, "%s", message);
	}
	else if(idx == LOG_XRECORD && cmdpid != xrecord_pid)
	{
		xrecord_pid = cmdpid;
		char message[256];
		strcpy(message, cmdname);
		strcat(message, NOTIFY_MSG_SCR);
		dbus_notify_signal(idx, cmdname, message);
		strcpy(message, LOG_XRECORD_BODY);
		strcat(message, cmdname);
		strcat(message, "\n");
		write_journal_log(LOG_CRIT, message, "");
		LogMessage(X_INFO, "%s", message);
	}
	else if(idx == LOG_CLIPBOARD && cmdpid != clipboard_pid)
	{
		clipboard_pid = cmdpid;
		char message[256];
		strcpy(message, cmdname);
		strcat(message, NOTIFY_MSG_CLP);
		dbus_notify_signal(idx, cmdname, message);;
		strcpy(message, LOG_CLIPBOARD_BODY);
		strcat(message, cmdname);
		strcat(message, "\n");
		write_journal_log(LOG_CRIT, message, "");
		LogMessage(X_INFO, "%s", message);
	}
	
	clock_gettime(CLOCK_REALTIME, &after);
	elapsed_secs = after.tv_sec - before.tv_sec;
	if(elapsed_secs > PID_SAVE_TIMEOUT)
	{
		renew_pid();
		timer = 0;
	}
}

static void *
XsmSetup(void *module, void *opts, int *errmaj, int *errmin)
{
	LoadExtensionList(XsmExt, ARRAY_SIZE(XsmExt), FALSE);
	LogMessage(X_INFO, "XsmSetup Called\n");
	return module;
}


static void 
XsmResource(CallbackListPtr *pcbl, void *unused, void *calldata){
	XaceResourceAccessRec *rec = calldata;
	int cid = CLIENT_ID(rec->id);
	Mask requested = rec->access_mode;
	Mask allowed = XsmResourceMask;
	const char *requestName, *resourceName;
	const char *cmdname, *cmdargs;
	pid_t cmdpid;


	requestName = XsmLookupRequestName(rec->client);
	resourceName = LookupResourceName(rec->rtype);

	cmdname = GetClientCmdName(rec->client);
	cmdargs = GetClientCmdArgs(rec->client);
	cmdpid = GetClientPid(rec->client);

	int request_client = rec->client->index;
    Bool is_foreign_window = (cid != request_client);

	if(requestName == NULL || cmdname == NULL)
		return;


	/* Check APIs of DixReadAccess */
	if(requested & DixReadAccess)
	{
		/* Restrict Screenshot via XSHM */
		if(is_foreign_window && !strcmp(requestName, "MIT-SHM:GetImage")){
			XsmAudit("XsmResource: client(%d) access(%lx) to resource(0x%lx) "
				"of client(%d) on request(%s) resource(%s) "
				"cmdname: %s(%d) args: %s\n", 
				rec->client->index,	(unsigned long)requested, 
				(unsigned long)rec->id, cid, requestName, resourceName,
				cmdname, cmdpid, cmdargs);

			if (is_blacklisted_screenshot(cmdname)) {
				rec->status = BadAccess;
				return;
			}
			if (is_whitelisted_screenshot(cmdname)) {
				return;
			}
			
			if((!policy_check(XSM_SCREENSHOT)))
			{
				if(!policy_check(XSM_SCREENSHOT)) make_log(LOG_SCREENSHOT, cmdpid, cmdname);
				rec->status = BadAccess;
			}
			return;
		}

		/* Restrict Screenshot via XGetImage (WINDOW) e.g. gtk2, gtk3, */
		if(is_foreign_window && !strcmp(requestName, "X11:GetImage"))
		{
			XsmAudit("XsmResource: client(%d) access(%lx) to resource(0x%lx) "
				"of client(%d) on request(%s) resource(%s) "
				"cmdname: %s(%d) args: %s\n", 
				rec->client->index,	(unsigned long)requested, 
				(unsigned long)rec->id, cid, requestName, resourceName,
				cmdname, cmdpid, cmdargs);

			if (is_blacklisted_screenshot(cmdname)) {
				rec->status = BadAccess;
				return;
			}
			if (is_whitelisted_screenshot(cmdname)) {
				return;
			}
			
			if(!policy_check(XSM_SCREENSHOT) && is_foreign_window)
			{
				make_log(LOG_SCREENSHOT, cmdpid, cmdname);
				rec->status = BadAccess;
			}
			return;
		}
		
		/* Restrict Screenshot via XGetImage (PIXMAP) e.g. screencloud, gnome-shell */
		if(rec->rtype == RT_PIXMAP && !strcmp(requestName, "X11:GetImage"))
		{
			XsmAudit("XsmResource: client(%d) access(%lx) to resource(0x%lx) "
				"of client(%d) on request(%s) resource(%s,%u) "
				"cmdname: %s(%d) args: %s\n", 
				rec->client->index,	(unsigned long)requested, 
				(unsigned long)rec->id, cid, requestName, resourceName, rec->rtype,
				cmdname, cmdpid, cmdargs);

			if (is_blacklisted_screenshot(cmdname)) {
				rec->status = BadAccess;
				return;
			}
			if (is_whitelisted_screenshot(cmdname)) {
				return;
			}

			if(!policy_check(XSM_SCREENSHOT) && is_foreign_window)
			{
				make_log(LOG_SCREENSHOT, cmdpid, cmdname);
				rec->status = BadAccess;
			}
			return;
		}


		/* Restrict Screenshot via gtk libraries and so on... */
		if((is_foreign_window) && !strcmp(requestName, "X11:CopyArea"))
		{
			XsmAudit("XsmResource: client(%d) access(%lx) to resource(0x%lx) "
				"of client(%d) on request(%s) resource(%s,%u) "
				"cmdname: %s(%d) args: %s\n", 
				rec->client->index,	(unsigned long)requested, 
				(unsigned long)rec->id, cid, requestName, resourceName, rec->rtype,
				cmdname, cmdpid, cmdargs);

			if (is_blacklisted_screenshot(cmdname)) {
				rec->status = BadAccess;
				return;
			}
			if (is_whitelisted_screenshot(cmdname)) {
				return;
			}
			
			if(!policy_check(XSM_SCREENSHOT) && is_foreign_window)
			{
				make_log(LOG_SCREENSHOT, cmdpid, cmdname);
				rec->status = BadAccess;
			}
			return;
		}
	}
}

/*
 * Control Xrecord and Xreplay
 *
 */

static void 
XsmExtension(CallbackListPtr *pcbl, void *unused, void *calldata)
{
	XaceExtAccessRec *rec = calldata;
	int i = 0;
	const char *requestName;
	const char *cmdname, *cmdargs;
	pid_t cmdpid;

	requestName = XsmLookupRequestName(rec->client);
	cmdname = GetClientCmdName(rec->client);
	cmdargs = GetClientCmdArgs(rec->client);
	cmdpid = GetClientPid(rec->client);

	if(requestName == NULL || cmdname == NULL)
		return;

	if(!strncmp(requestName, "RECORD:", 7)) {
		XsmAudit("XsmExtension: client %d access to extension "
		 		 "%s on request %s cmdname %s(%d) args %s\n",
				 rec->client->index, rec->ext->name,
				 requestName,
				 cmdname, cmdpid, cmdargs);
	}

	/* Restrict Xsession Record & Replay */
	if((!strcmp(requestName, "XTEST:GrabControl") || 
		!strcmp(requestName, "XTEST:FakeInput") ||
		!strcmp(requestName, "RECORD:CreateContext") || 
		!strcmp(requestName, "RECORD:EnableContext"))){

		XsmAudit("XsmExtension: client %d access to extension "
				"%s on request %s cmdname %s(%d) args %s\n",
				rec->client->index, rec->ext->name,
				requestName,
				cmdname, cmdpid, cmdargs);

		if (is_blacklisted_xrecord(cmdname)) {
            rec->status = BadAccess;
            return;
        }
        if (is_whitelisted_xrecord(cmdname)) {
            return;
        }
		
		if(!policy_check(XSM_XRECORD))
		{
			make_log(LOG_XRECORD, cmdpid, cmdname);
			rec->status = BadAccess;
		}
		return;
	}
	/* Restrict Screencast (Cursor Image) e.g. recordmydesktop, kazam */
	else if(!strcmp(requestName, "XFIXES:GetCursorImageAndName"))
	{
		XsmAudit("XsmExtension: client %d access to extension "
				"%s on request %s cmdname %s(%d) args %s\n",
				rec->client->index, rec->ext->name,
				requestName,
				cmdname, cmdpid, cmdargs);

		if (is_blacklisted_screencast(cmdname)) {
            rec->status = BadAccess;
            return;
        }
        if (is_whitelisted_screencast(cmdname)) {
            return;
        }
		
		if(!policy_check(XSM_SCREENCAST))
		{
			make_log(LOG_SCREENCAST, cmdpid, cmdname);
			rec->status = BadAccess;
		}
		return;
	}

}


/*
 * Control clipboard behaviors
 * 
 */

/*
 
"include/selection.h" 

typedef struct _Selection {
	Atom selection;
	TimeStamp lastTimeChanged;
	Window window;
	WindowPtr pWin;
	ClientPtr client;
	struct _Selection *next;
	PrivateRec *devPrivates;
} Selection;
*/

static void
XsmSelection(CallbackListPtr *pcbl, void *unused, void *calldata)
{
	XaceSelectionAccessRec *rec = calldata;
	Selection *pSel = *rec->ppSel;
	Atom name = pSel->selection;
	Mask access_mode = rec->access_mode;
	const char *cmdname, *cmdargs;
	pid_t cmdpid;
	const char *atomname, *requestName;

	cmdname = GetClientCmdName(rec->client);
	cmdargs = GetClientCmdArgs(rec->client);
	cmdpid = GetClientPid(rec->client);

	requestName = XsmLookupRequestName(rec->client);
	atomname = NameForAtom(name);

	if(cmdname == NULL || atomname == NULL || requestName == NULL)
		return;

	if(!strcmp(atomname, "CLIPBOARD") && (pSel->window == 0x0))
	{
		/*
		XsmAudit("XsmSelection: client %d access to server configuration request %s "
				"atom %s(%p) window(%p)"
				"cmdname %s(%d) args %s\n", 
				rec->client->index, requestName,
				NameForAtom(name), name, pSel->window,
				cmdname, cmdpid, cmdargs);
		*/
		
		/* Kill clipboard application */
		if(!strcmp(cmdname, "clipit") || !strcmp(cmdname, "xclip"))
		{
			XsmAudit("XsmSelection: client %d cmdname %s(%d) killed\n"
					,rec->client->index, cmdname, cmdpid);

			rec->status = BadAccess;
			kill(cmdpid, SIGKILL);
		}
	}
	
	/* Restrict Clipboard on Window (GUI Client) */
	if(!strcmp(atomname, "CLIPBOARD") && !strcmp(requestName, "X11:GetSelectionOwner") &&
		(pSel->window != 0x0)){

		XsmAudit("XsmSelection: client %d access to server configuration request %s "
				"atom %s(%u) window(%d) "
				"cmdname %s(%d) args %s\n", 
				rec->client->index, requestName,
				NameForAtom(name), name, pSel->window,
				cmdname, cmdpid, cmdargs);

		if (is_blacklisted_clipboard(cmdname)) {
            rec->status = BadAccess;
            return;
        }
        if (is_whitelisted_clipboard(cmdname)) {
            return;
        }

		if(!policy_check(XSM_CLIPBOARD))
		{
			make_log(LOG_CLIPBOARD, cmdpid, cmdname);
		
			/* Delete Any Selections */
			DeleteWindowFromAnySelections(pSel->pWin);
			DeleteClientFromAnySelections(rec->client);
			
			/* Kill clipboard application */
			if(!strcmp(cmdname, "clipit") || !strcmp(cmdname, "xclip"))
			{
				XsmAudit("XsmSelection: client %d cmdname %s(%d) killed\n"
						,rec->client->index, cmdname, cmdpid);

				rec->status = BadAccess;
				kill(cmdpid, SIGKILL);
			}
		}

	}
}

static void 
XsmResetProc(ExtensionEntry * extEntry)
{
	/* Unregister callbacks */
	XaceDeleteCallback(XACE_EXT_DISPATCH, XsmExtension, NULL);
	XaceDeleteCallback(XACE_RESOURCE_ACCESS, XsmResource, NULL);
	XaceDeleteCallback(XACE_EXT_ACCESS, XsmExtension, NULL);
	XaceDeleteCallback(XACE_SELECTION_ACCESS, XsmSelection, NULL);
}



/* extension function called from client */
static int
ProcXsm(ClientPtr client){
	const char *cmdname, *cmdargs;
	pid_t cmdpid;

	cmdname = GetClientCmdName(client);
	cmdargs = GetClientCmdArgs(client);
	cmdpid = GetClientPid(client);

	LogMessage(X_INFO, 
				"ProcXsm call from %s(%d) args:%s\n"
				, cmdname, cmdpid, cmdargs);
	return Success;
}


void
XsmExtensionInit(void)
{
	ExtensionEntry *extEntry;
	int ret = TRUE;

	LogMessage(X_INFO, "XsmExtensionInit() Called\n");

	/* Read Xsm policy file */
	read_policy();

	read_list(WHITELIST_SCREENSHOT, whitelist_screenshot, &whitelist_screenshot_count);
    read_list(WHITELIST_SCREENCAST, whitelist_screencast, &whitelist_screencast_count);
    read_list(WHITELIST_XRECORD,    whitelist_xrecord,    &whitelist_xrecord_count);
    read_list(WHITELIST_CLIPBOARD,  whitelist_clipboard,  &whitelist_clipboard_count);

    read_list(BLACKLIST_SCREENSHOT, blacklist_screenshot, &blacklist_screenshot_count);
    read_list(BLACKLIST_SCREENCAST, blacklist_screencast, &blacklist_screencast_count);
    read_list(BLACKLIST_XRECORD,    blacklist_xrecord,    &blacklist_xrecord_count);
    read_list(BLACKLIST_CLIPBOARD,  blacklist_clipboard,  &blacklist_clipboard_count);

	/* Run inotify policy loader */
	inotify_policy();
	/* 
		X Access Control Extension Security hooks
		Constants used to identify the available security hooks

		#define XACE_CORE_DISPATCH		0
		#define XACE_EXT_DISPATCH       1
		#define XACE_RESOURCE_ACCESS    2
		#define XACE_DEVICE_ACCESS      3
		#define XACE_PROPERTY_ACCESS    4
		#define XACE_SEND_ACCESS        5
		#define XACE_RECEIVE_ACCESS     6
		#define XACE_CLIENT_ACCESS      7
		#define XACE_EXT_ACCESS         8
		#define XACE_SERVER_ACCESS      9
		#define XACE_SELECTION_ACCESS   10
		#define XACE_SCREEN_ACCESS      11
		#define XACE_SCREENSAVER_ACCESS 12
		#define XACE_AUTH_AVAIL         13
		#define XACE_KEY_AVAIL          14
		#define XACE_NUM_HOOKS          15
	*/
	
	ret &= XaceRegisterCallback(XACE_EXT_DISPATCH, XsmExtension, NULL);
	ret &= XaceRegisterCallback(XACE_RESOURCE_ACCESS, XsmResource, NULL);
	ret &= XaceRegisterCallback(XACE_EXT_ACCESS, XsmExtension, NULL);
	ret &= XaceRegisterCallback(XACE_SELECTION_ACCESS, XsmSelection, NULL);

	if (!ret)
		FatalError("XsmExtensionInit: Failed to register callbacks\n");
	
	extEntry = AddExtension("xsm", 
							1, 2,
							ProcXsm, ProcXsm,
							XsmResetProc, StandardMinorOpcode);
	
	XsmErrorBase = extEntry->errorBase;
    XsmEventBase = extEntry->eventBase;
	
} 
