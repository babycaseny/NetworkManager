/* NetworkManager system settings service
 *
 * Søren Sandmann <sandmann@daimi.au.dk>
 * Dan Williams <dcbw@redhat.com>
 * Tambet Ingo <tambet@gmail.com>
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License along
 * with this program; if not, write to the Free Software Foundation, Inc.,
 * 51 Franklin Street, Fifth Floor, Boston, MA 02110-1301 USA.
 *
 * (C) Copyright 2007 - 2011 Red Hat, Inc.
 * (C) Copyright 2008 Novell, Inc.
 */

#include "nm-default.h"

#include "nm-settings.h"

#include <unistd.h>
#include <sys/stat.h>
#include <gmodule.h>
#include <pwd.h>

#if HAVE_SELINUX
#include <selinux/selinux.h>
#endif

#include "nm-libnm-core-intern/nm-common-macros.h"
#include "nm-glib-aux/nm-keyfile-aux.h"
#include "nm-dbus-interface.h"
#include "nm-connection.h"
#include "nm-setting-8021x.h"
#include "nm-setting-bluetooth.h"
#include "nm-setting-cdma.h"
#include "nm-setting-connection.h"
#include "nm-setting-gsm.h"
#include "nm-setting-ip4-config.h"
#include "nm-setting-ip6-config.h"
#include "nm-setting-olpc-mesh.h"
#include "nm-setting-ppp.h"
#include "nm-setting-pppoe.h"
#include "nm-setting-serial.h"
#include "nm-setting-vpn.h"
#include "nm-setting-wired.h"
#include "nm-setting-adsl.h"
#include "nm-setting-wireless.h"
#include "nm-setting-wireless-security.h"
#include "nm-setting-proxy.h"
#include "nm-setting-bond.h"
#include "nm-utils.h"
#include "nm-core-internal.h"

#include "nm-glib-aux/nm-c-list.h"
#include "nm-dbus-object.h"
#include "devices/nm-device-ethernet.h"
#include "nm-settings-connection.h"
#include "nm-settings-plugin.h"
#include "nm-dbus-manager.h"
#include "nm-auth-utils.h"
#include "nm-auth-subject.h"
#include "nm-session-monitor.h"
#include "plugins/keyfile/nms-keyfile-plugin.h"
#include "plugins/keyfile/nms-keyfile-storage.h"
#include "nm-agent-manager.h"
#include "nm-config.h"
#include "nm-audit-manager.h"
#include "NetworkManagerUtils.h"
#include "nm-dispatcher.h"
#include "nm-hostname-manager.h"

/*****************************************************************************/

#define EXPORT(sym) void * __export_##sym = &sym;

EXPORT(nm_settings_connection_get_type)
EXPORT(nm_settings_connection_update)

/*****************************************************************************/

static NM_CACHED_QUARK_FCN ("default-wired-connection", _default_wired_connection_quark)
static NM_CACHED_QUARK_FCN ("default-wired-device", _default_wired_device_quark)

/*****************************************************************************/

static guint64
STORAGE_OBFUSCATE_PTR (const NMSettingsStorage *storage)
{
	return nm_hash_obfuscate_ptr (1950954253u, storage);
}

/*****************************************************************************/

typedef struct {
	const char *uuid;
	NMSettingsConnection *sett_conn;
	NMSettingsStorage *storage;
	CList shadowed_storages_lst_head;
	char _uuid_data[];
} SettConnEntry;

static SettConnEntry *
_sett_conn_entry_new (const char *uuid)
{
	SettConnEntry *sett_conn_entry;
	gsize l_p_1;

	l_p_1 = strlen (uuid) + 1;

	sett_conn_entry = g_malloc (sizeof (SettConnEntry) + l_p_1);
	sett_conn_entry->uuid = sett_conn_entry->_uuid_data;
	sett_conn_entry->sett_conn = NULL;
	sett_conn_entry->storage = NULL;
	c_list_init (&sett_conn_entry->shadowed_storages_lst_head);
	memcpy (sett_conn_entry->_uuid_data, uuid, l_p_1);
	return sett_conn_entry;
}

static void
_sett_conn_entry_free (SettConnEntry *sett_conn_entry)
{
	nm_c_list_elem_free_all (&sett_conn_entry->shadowed_storages_lst_head, g_object_unref);
	nm_g_object_unref (sett_conn_entry->sett_conn);
	nm_g_object_unref (sett_conn_entry->storage);
	g_free (sett_conn_entry);
}

static NMSettingsConnection *
_sett_conn_entry_get_conn (SettConnEntry *sett_conn_entry)
{
	return sett_conn_entry ? sett_conn_entry->sett_conn : NULL;
}

/*****************************************************************************/

NM_GOBJECT_PROPERTIES_DEFINE (NMSettings,
	PROP_UNMANAGED_SPECS,
	PROP_HOSTNAME,
	PROP_CAN_MODIFY,
	PROP_CONNECTIONS,
	PROP_STARTUP_COMPLETE,
);

enum {
	CONNECTION_ADDED,
	CONNECTION_UPDATED,
	CONNECTION_REMOVED,
	CONNECTION_FLAGS_CHANGED,
	LAST_SIGNAL
};

static guint signals[LAST_SIGNAL] = { 0 };

typedef struct {
	NMAgentManager *agent_mgr;

	NMConfig *config;

	NMHostnameManager *hostname_manager;

	NMSessionMonitor *session_monitor;

	CList auth_lst_head;

	NMSKeyfilePlugin *keyfile_plugin;

	GSList *plugins;

	NMKeyFileDB *kf_db_timestamps;
	NMKeyFileDB *kf_db_seen_bssids;

	GHashTable *sett_conn_entries;

	CList connections_lst_head;

	NMSettingsConnection **connections_cached_list;

	GSList *unmanaged_specs;
	GSList *unrecognized_specs;

	NMSettingsConnection *startup_complete_blocked_by;

	guint connections_len;

	guint connections_generation;

	guint kf_db_flush_idle_id_timestamps;
	guint kf_db_flush_idle_id_seen_bssids;

	bool started:1;
	bool startup_complete:1;

} NMSettingsPrivate;

struct _NMSettings {
	NMDBusObject parent;
	NMSettingsPrivate _priv;
};

struct _NMSettingsClass {
	NMDBusObjectClass parent;
};

G_DEFINE_TYPE (NMSettings, nm_settings, NM_TYPE_DBUS_OBJECT);

#define NM_SETTINGS_GET_PRIVATE(self) _NM_GET_PRIVATE (self, NMSettings, NM_IS_SETTINGS)

/*****************************************************************************/

#define _NMLOG_DOMAIN         LOGD_SETTINGS
#define _NMLOG(level, ...) __NMLOG_DEFAULT (level, _NMLOG_DOMAIN, "settings", __VA_ARGS__)

/*****************************************************************************/

static const NMDBusInterfaceInfoExtended interface_info_settings;
static const GDBusSignalInfo signal_info_new_connection;
static const GDBusSignalInfo signal_info_connection_removed;

static void _startup_complete_connection_ready_changed_cb (NMSettingsConnection *conn,
                                                           GParamSpec *pspec,
                                                           gpointer user_data);

static void default_wired_clear_tag (NMSettings *self,
                                     NMDevice *device,
                                     NMSettingsConnection *sett_conn,
                                     gboolean add_to_no_auto_default);

static void _clear_connections_cached_list (NMSettingsPrivate *priv);

/*****************************************************************************/

static void
_emit_connection_added (NMSettings *self,
                        NMSettingsConnection *sett_conn)
{
	g_signal_emit (self, signals[CONNECTION_ADDED], 0, sett_conn);
}

static void
_emit_connection_updated (NMSettings *self,
                          NMSettingsConnection *sett_conn,
                          gboolean by_user)
{
	g_signal_emit (self, signals[CONNECTION_UPDATED], 0, sett_conn, by_user);
}

static void
_emit_connection_removed (NMSettings *self,
                          NMSettingsConnection *sett_conn)
{
	g_signal_emit (self, signals[CONNECTION_REMOVED], 0, sett_conn);
}

static void
_emit_connection_flags_changed (NMSettings *self,
                                NMSettingsConnection *sett_conn)
{
	g_signal_emit (self, signals[CONNECTION_FLAGS_CHANGED], 0, sett_conn);
}

/*****************************************************************************/

static void
_startup_complete_check (NMSettings *self)
{
	NMSettingsPrivate *priv = NM_SETTINGS_GET_PRIVATE (self);
	NMSettingsConnection *sett_conn;

	if (priv->startup_complete)
		return;

	c_list_for_each_entry (sett_conn, &priv->connections_lst_head, _connections_lst) {
		if (!nm_settings_connection_get_ready (sett_conn)) {
			nm_g_object_ref_set (&priv->startup_complete_blocked_by, sett_conn);
			return;
		}
	}

	g_clear_object (&priv->startup_complete_blocked_by);

	/* the _startup_complete_connection_ready_changed_cb signal handler is no longer needed. */
	c_list_for_each_entry (sett_conn, &priv->connections_lst_head, _connections_lst)
		g_signal_handlers_disconnect_by_func (sett_conn, G_CALLBACK (_startup_complete_connection_ready_changed_cb), self);

	priv->startup_complete = TRUE;
	_notify (self, PROP_STARTUP_COMPLETE);
}

static void
_startup_complete_connection_ready_changed_cb (NMSettingsConnection *conn,
                                               GParamSpec *pspec,
                                               gpointer user_data)
{
	NMSettings *self = NM_SETTINGS (user_data);

	if (nm_settings_connection_get_ready (conn))
		_startup_complete_check (self);
}

const char *
nm_settings_get_startup_complete_blocked_reason (NMSettings *self)
{
	NMSettingsPrivate *priv = NM_SETTINGS_GET_PRIVATE (self);
	const char *uuid = NULL;

	if (priv->startup_complete)
		return NULL;
	if (priv->startup_complete_blocked_by)
		uuid = nm_settings_connection_get_uuid (priv->startup_complete_blocked_by);
	return uuid ?: "unknown";
}

/*****************************************************************************/

const GSList *
nm_settings_get_unmanaged_specs (NMSettings *self)
{
	NMSettingsPrivate *priv = NM_SETTINGS_GET_PRIVATE (self);

	return priv->unmanaged_specs;
}

static gboolean
update_specs (NMSettings *self, GSList **specs_ptr,
              GSList * (*get_specs_func) (NMSettingsPlugin *))
{
	NMSettingsPrivate *priv = NM_SETTINGS_GET_PRIVATE (self);
	GSList *new = NULL;
	GSList *iter;

	for (iter = priv->plugins; iter; iter = g_slist_next (iter)) {
		GSList *specs;

		specs = get_specs_func (iter->data);
		while (specs) {
			GSList *s = specs;

			specs = g_slist_remove_link (specs, s);
			if (nm_utils_g_slist_find_str (new, s->data)) {
				g_free (s->data);
				g_slist_free_1 (s);
				continue;
			}
			s->next = new;
			new = s;
		}
	}

	if (nm_utils_g_slist_strlist_cmp (new, *specs_ptr) == 0) {
		g_slist_free_full (new, g_free);
		return FALSE;
	}

	g_slist_free_full (*specs_ptr, g_free);
	*specs_ptr = new;
	return TRUE;

}

static void
_plugin_unmanaged_specs_changed (NMSettingsPlugin *config,
                                 gpointer user_data)
{
	NMSettings *self = NM_SETTINGS (user_data);
	NMSettingsPrivate *priv = NM_SETTINGS_GET_PRIVATE (self);

	if (update_specs (self, &priv->unmanaged_specs,
	                  nm_settings_plugin_get_unmanaged_specs))
		_notify (self, PROP_UNMANAGED_SPECS);
}

static void
_plugin_unrecognized_specs_changed (NMSettingsPlugin *config,
                                    gpointer user_data)
{
	NMSettings *self = NM_SETTINGS (user_data);
	NMSettingsPrivate *priv = NM_SETTINGS_GET_PRIVATE (self);

	update_specs (self, &priv->unrecognized_specs,
	              nm_settings_plugin_get_unrecognized_specs);
}

/*****************************************************************************/

static void
connection_flags_changed (NMSettingsConnection *sett_conn,
                          gpointer user_data)
{
	_emit_connection_flags_changed (NM_SETTINGS (user_data), sett_conn);
}

/*****************************************************************************/

static void
_do_sett_conn_entires_addremove (NMSettings *self,
                                 SettConnEntry *sett_conn_entry,
                                 gboolean do_add /* or else remove */)
{
	NMSettingsPrivate *priv = NM_SETTINGS_GET_PRIVATE (self);

	/* the sett-conn-enties keep @self alive. There is not particularly
	 * strong reason, because during shutdown all setting plugins should
	 * properly unregister, thus this should have no effect in practice. */
	if (do_add) {
		if (!g_hash_table_add (priv->sett_conn_entries, sett_conn_entry))
			nm_assert_not_reached ();
		else if (g_hash_table_size (priv->sett_conn_entries) == 1)
			g_object_ref (self);
	} else {
		if (!g_hash_table_remove (priv->sett_conn_entries, sett_conn_entry))
			nm_assert_not_reached ();
		else if (g_hash_table_size (priv->sett_conn_entries) == 0)
			g_object_unref (self);
	}
}

static void
_connection_changed_update (NMSettings *self,
                            SettConnEntry *sett_conn_entry,
                            NMConnection *connection_to_add,
                            gboolean by_user)
{
	NMSettingsPrivate *priv = NM_SETTINGS_GET_PRIVATE (self);
	gs_unref_object NMConnection *connection_old = NULL;
	NMSettingsConnection *sett_conn;
	gboolean is_adding = FALSE;
	const char *path;

	sett_conn = sett_conn_entry->sett_conn;
	is_adding = (sett_conn == NULL);

	if (is_adding) {
		sett_conn = nm_settings_connection_new ();

		_nm_settings_connection_register_kf_dbs (sett_conn,
		                                         priv->kf_db_timestamps,
		                                         priv->kf_db_seen_bssids);

		_nm_settings_connection_set_storage (sett_conn, sett_conn_entry->storage, NULL);
		_nm_settings_connection_set_filename (sett_conn, nm_settings_storage_get_filename (sett_conn_entry->storage));

		_nm_settings_connection_set_connection (sett_conn, connection_to_add, NULL);

		_clear_connections_cached_list (priv);
		c_list_link_tail (&priv->connections_lst_head, &sett_conn->_connections_lst);
		priv->connections_len++;
		priv->connections_generation++;

		sett_conn_entry->sett_conn = sett_conn;

		g_signal_connect (sett_conn, NM_SETTINGS_CONNECTION_FLAGS_CHANGED, G_CALLBACK (connection_flags_changed), self);

		if (!priv->startup_complete) {
			g_signal_connect (sett_conn, "notify::" NM_SETTINGS_CONNECTION_READY,
			                  G_CALLBACK (_startup_complete_connection_ready_changed_cb),
			                  self);
		}
	} else {
		_nm_settings_connection_set_storage (sett_conn, sett_conn_entry->storage, NULL);
		_nm_settings_connection_set_filename (sett_conn, nm_settings_storage_get_filename (sett_conn_entry->storage));

		if (!nm_connection_compare (nm_settings_connection_get_connection (sett_conn),
		                            connection_to_add,
		                            NM_SETTING_COMPARE_FLAG_EXACT))
			_nm_settings_connection_set_connection (sett_conn, connection_to_add, &connection_old);
	}

	nm_settings_connection_recheck_visibility (sett_conn, priv->session_monitor);

	if (is_adding) {
		/* FIXME(shutdown): The NMSettings instance can't be disposed
		 * while there is any exported connection. Ideally we should
		 * unexport all connections on NMSettings' disposal, but for now
		 * leak @self on termination when there are connections alive. */
		path = nm_dbus_object_export (NM_DBUS_OBJECT (sett_conn));
	} else
		path = nm_dbus_object_get_path (NM_DBUS_OBJECT (sett_conn));

	if (   is_adding
	    || connection_old) {
		nm_utils_log_connection_diff (nm_settings_connection_get_connection (sett_conn),
		                              connection_old,
		                              LOGL_DEBUG,
		                              LOGD_CORE,
		                              is_adding ? "new connection" : "update connection",
		                              "++ ",
		                              path);
	}

	if (is_adding) {
		nm_dbus_object_emit_signal (NM_DBUS_OBJECT (self),
		                            &interface_info_settings,
		                            &signal_info_new_connection,
		                            "(o)",
		                            path);
		_emit_connection_added (self, sett_conn);
		_notify (self, PROP_CONNECTIONS);
	} else
		_emit_connection_updated (self, sett_conn, by_user);
}

static void
_connection_changed_delete (NMSettings *self,
                            SettConnEntry *sett_conn_entry)
{
	NMSettingsPrivate *priv = NM_SETTINGS_GET_PRIVATE (self);
	gs_unref_object NMSettingsConnection *sett_conn = NULL;
	gs_unref_object NMSettingsStorage *storage = NULL;
	gs_unref_object NMConnection *old_connection = NULL;
	gs_unref_object NMConnection *connection_for_agents = NULL;
	NMDevice *device;
	const char *uuid;

	nm_assert (sett_conn_entry);
	nm_assert_valid_settings_storage (NULL, sett_conn_entry->storage);
	nm_assert (NM_IS_SETTINGS_CONNECTION (sett_conn_entry->sett_conn));
	nm_assert (c_list_contains (&priv->connections_lst_head, &sett_conn_entry->sett_conn->_connections_lst));
	nm_assert (nm_dbus_object_is_exported (NM_DBUS_OBJECT (sett_conn_entry->sett_conn)));

	sett_conn = g_steal_pointer (&sett_conn_entry->sett_conn);
	storage = g_steal_pointer (&sett_conn_entry->storage);
	if (c_list_is_empty (&sett_conn_entry->shadowed_storages_lst_head))
		_do_sett_conn_entires_addremove (self, sett_conn_entry, FALSE);

	uuid = nm_settings_storage_get_uuid (storage);

	/* When the default wired sett_conn is removed (either deleted or saved to
	 * a new persistent sett_conn by a plugin), write the MAC address of the
	 * wired device to the config file and don't create a new default wired
	 * sett_conn for that device again.
	 */
	device = g_object_get_qdata (G_OBJECT (sett_conn), _default_wired_device_quark ());
	if (device)
		default_wired_clear_tag (self, device, sett_conn, TRUE);

	g_signal_handlers_disconnect_by_func (sett_conn, G_CALLBACK (connection_flags_changed), self);
	if (!priv->startup_complete)
		g_signal_handlers_disconnect_by_func (sett_conn, G_CALLBACK (_startup_complete_connection_ready_changed_cb), self);

	_clear_connections_cached_list (priv);
	c_list_unlink (&sett_conn->_connections_lst);
	priv->connections_len--;
	priv->connections_generation++;

	/* Tell agents to remove secrets for this connection */
	connection_for_agents = nm_simple_connection_new_clone (nm_settings_connection_get_connection (sett_conn));
	nm_connection_clear_secrets (connection_for_agents);
	nm_agent_manager_delete_secrets (priv->agent_mgr,
	                                 nm_dbus_object_get_path (NM_DBUS_OBJECT (self)),
	                                 connection_for_agents);

	_notify (self, PROP_CONNECTIONS);
	nm_dbus_object_emit_signal (NM_DBUS_OBJECT (self),
	                            &interface_info_settings,
	                            &signal_info_connection_removed,
	                            "(o)",
	                            nm_dbus_object_get_path (NM_DBUS_OBJECT (sett_conn)));

	nm_dbus_object_unexport (NM_DBUS_OBJECT (sett_conn));

	_nm_settings_connection_set_visible (sett_conn, FALSE);

	_emit_connection_removed (self, sett_conn);

	_startup_complete_check (self);

	nm_key_file_db_remove_key (priv->kf_db_timestamps, uuid);
	nm_key_file_db_remove_key (priv->kf_db_seen_bssids, uuid);
}

static NMConnection *
_connection_changed_normalize_connection (NMSettingsStorage *storage,
                                          NMConnection *connection,
                                          GVariant *secrets_to_merge,
                                          NMConnection **out_connection_cloned)
{
	gs_unref_object NMConnection *connection_cloned = NULL;
	gs_free_error GError *error = NULL;
	const char *uuid;

	nm_assert (NM_IS_SETTINGS_STORAGE (storage));
	nm_assert (out_connection_cloned && !*out_connection_cloned);

	if (!connection)
		return NULL;

	nm_assert (NM_IS_CONNECTION (connection));

	uuid = nm_settings_storage_get_uuid (storage);

	if (secrets_to_merge) {
		connection_cloned = nm_simple_connection_new_clone (connection);
		connection = connection_cloned;
		nm_connection_update_secrets (connection,
		                              NULL,
		                              secrets_to_merge,
		                              NULL);
	}

	if (!_nm_connection_ensure_normalized (connection,
	                                       !!connection_cloned,
	                                       uuid,
	                                       FALSE,
	                                       connection_cloned ? NULL : &connection_cloned,
	                                       &error)) {
		/* this is most likely a bug in the plugin. It provided a connection that no longer verifies.
		 * Well, I guess it could also happen when we merge @secrets_to_merge above. In any case
		 * somewhere is a bug. */
		_LOGT ("storage-changed[%s,"NM_HASH_OBFUSCATE_PTR_FMT"]: plugin provided an invalid connection: %s",
		       uuid,
		       STORAGE_OBFUSCATE_PTR (storage),
		       error->message);
		return NULL;
	}
	if (connection_cloned)
		connection = connection_cloned;

	*out_connection_cloned = g_steal_pointer (&connection_cloned);
	return connection;
}

static gboolean
_connection_changed_prepare (NMSettings *self,
                             NMSettingsStorage *storage,
                             NMConnection *connection,
                             gboolean force_replace,
                             SettConnEntry **out_sett_conn_entry,
                             gboolean *out_to_delete)
{
	NMSettingsPrivate *priv = NM_SETTINGS_GET_PRIVATE (self);
	gs_free_error GError *error = NULL;
	SettConnEntry *sett_conn_entry;
	NMCListElem *shadowed_storage_elem;
	gboolean was_in_shadowed_storage;
	const char *uuid;

	nm_assert_valid_settings_storage (NULL, storage);
	nm_assert (!connection || NM_IS_CONNECTION (connection));
	nm_assert (out_sett_conn_entry);
	nm_assert (out_to_delete);

	*out_sett_conn_entry = NULL;

	uuid = nm_settings_storage_get_uuid (storage);

	nm_assert (nm_utils_is_uuid (uuid));

	sett_conn_entry = g_hash_table_lookup (priv->sett_conn_entries, &uuid);

	if (!connection) {
		if (   !sett_conn_entry
		    || sett_conn_entry->storage != storage) {

			shadowed_storage_elem =   sett_conn_entry
			                        ? nm_c_list_elem_find_first (&sett_conn_entry->shadowed_storages_lst_head, storage)
			                        : NULL;

			_LOGT ("storage-changed[%s,"NM_HASH_OBFUSCATE_PTR_FMT"]: ignore deletion of %s connection",
			       uuid,
			       STORAGE_OBFUSCATE_PTR (storage),
			       shadowed_storage_elem ? "shadowed" : "unknown");
			if (shadowed_storage_elem) {
				nm_c_list_elem_free_full (shadowed_storage_elem, g_object_unref);
				if (c_list_is_empty (&sett_conn_entry->shadowed_storages_lst_head))
					_do_sett_conn_entires_addremove (self, sett_conn_entry, FALSE);
			}
			return FALSE;
		}

		_LOGT ("storage-changed[%s,"NM_HASH_OBFUSCATE_PTR_FMT"]: delete connection%s",
		       uuid,
		       STORAGE_OBFUSCATE_PTR (storage),
		         c_list_is_empty (&sett_conn_entry->shadowed_storages_lst_head)
		       ? ""
		       : " (has shadowed connections)");

		*out_sett_conn_entry = sett_conn_entry;
		*out_to_delete = TRUE;
		return TRUE;
	}

#if NM_MORE_ASSERTS > 5
	if (connection) {
		gboolean modified = TRUE;

		if (   !nm_connection_normalize (connection, NULL, &modified, NULL)
		    || modified) {
			/* the connection must verify and be normalized. That is because we
			 * keep a reference to the instance and don't clone it.
			 *
			 * But we also don't want to normalize an input. The caller should
			 * do that for us. */
			nm_assert_not_reached ();
		}

		nm_assert (nm_streq0 (uuid, nm_connection_get_uuid (connection)));
	}
#endif

	if (   sett_conn_entry
	    && sett_conn_entry->storage
	    && sett_conn_entry->storage != storage
	    && !force_replace) {

		/* multiple NMSettingsStorage instances claim the same UUID. We need to handle that,
		 * and need to prioritize which one to expose.
		 *
		 * In the future we might need something more sophisticated, where we want to swich
		 * from one storage (backend/plugin) to another.
		 *
		 * Currently we do something very simple. Unless the new event is @force_replace,
		 * we stick to the first/principle/main one all the time, until:
		 *
		 *   - the first got removed
		 *   - we receive yet another event for the storage (which unshadows it).
		 *
		 * That's the reason we keep track of the shadowed storages in shadowed_storages_lst_head.
		 */

		shadowed_storage_elem = nm_c_list_elem_find_first (&sett_conn_entry->shadowed_storages_lst_head, storage);

		if (!shadowed_storage_elem) {
			c_list_link_tail (&sett_conn_entry->shadowed_storages_lst_head,
			                  &nm_c_list_elem_new_stale (g_object_ref (storage))->lst);
		}

		_LOGT ("storage-changed[%s,"NM_HASH_OBFUSCATE_PTR_FMT"]: update shadowed connection%s",
		       uuid,
		       STORAGE_OBFUSCATE_PTR (storage),
		       shadowed_storage_elem ? " again" : "");
		return FALSE;
	}

	nmtst_connection_assert_unchanging (connection);

	was_in_shadowed_storage = FALSE;
	if (!sett_conn_entry) {
		sett_conn_entry = _sett_conn_entry_new (uuid);
		_do_sett_conn_entires_addremove (self, sett_conn_entry, TRUE);
	} else {
		shadowed_storage_elem = nm_c_list_elem_find_first (&sett_conn_entry->shadowed_storages_lst_head, storage);
		if (shadowed_storage_elem) {
			was_in_shadowed_storage = TRUE;
			nm_c_list_elem_free_full (shadowed_storage_elem, g_object_unref);
		}
	}

	if (!sett_conn_entry->storage) {
		nm_assert (!sett_conn_entry->sett_conn);
		sett_conn_entry->storage = g_object_ref (storage);
		_LOGT ("storage-changed[%s,"NM_HASH_OBFUSCATE_PTR_FMT"]: add connection%s",
		       uuid,
		       STORAGE_OBFUSCATE_PTR (storage),
		       was_in_shadowed_storage ? " (was shadowed before)" : "");
	} else if (sett_conn_entry->storage != storage) {
		nm_assert (NM_IS_SETTINGS_CONNECTION (sett_conn_entry->sett_conn));
		_LOGT ("storage-changed[%s,"NM_HASH_OBFUSCATE_PTR_FMT"]: update connection (shadowing existing storage "NM_HASH_OBFUSCATE_PTR_FMT")%s",
		       uuid,
		       STORAGE_OBFUSCATE_PTR (storage),
		       STORAGE_OBFUSCATE_PTR (sett_conn_entry->storage),
		       was_in_shadowed_storage ? " (was shadowed before)" : "");
		c_list_link_front (&sett_conn_entry->shadowed_storages_lst_head,
		                   &nm_c_list_elem_new_stale (g_object_ref (g_steal_pointer (&sett_conn_entry->storage)))->lst);
		sett_conn_entry->storage = g_object_ref (storage);
	} else {
		nm_assert (NM_IS_SETTINGS_CONNECTION (sett_conn_entry->sett_conn));
		_LOGT ("storage-changed[%s,"NM_HASH_OBFUSCATE_PTR_FMT"]: update connection",
		       uuid,
		       STORAGE_OBFUSCATE_PTR (storage));
	}

	*out_sett_conn_entry = sett_conn_entry;
	*out_to_delete = FALSE;
	return TRUE;
}

static void
_plugin_reload_connections_cb (NMSettingsPlugin *plugin,
                               NMSettingsStorage *storage,
                               NMConnection *connection,
                               gpointer user_data)
{
	NMSettings *self = user_data;
	gs_unref_object NMConnection *connection_cloned = NULL;
	SettConnEntry *sett_conn_entry;
	gboolean to_delete;

	connection = _connection_changed_normalize_connection (storage,
	                                                       connection,
	                                                       NULL,
	                                                       &connection_cloned);
	if (_connection_changed_prepare (self,
	                                 storage,
	                                 connection,
	                                 nm_settings_storage_is_in_memory (storage),
	                                 &sett_conn_entry,
	                                 &to_delete)) {
		if (to_delete)
			_connection_changed_delete (self, sett_conn_entry);
		else
			_connection_changed_update (self, sett_conn_entry, connection, TRUE);
	}
}

/*****************************************************************************/

static gboolean
_add_connection_to_first_plugin (NMSettings *self,
                                 NMConnection *new_connection,
                                 gboolean in_memory,
                                 NMSettingsStorage **out_new_storage,
                                 NMConnection **out_new_connection,
                                 GError **error)
{
	NMSettingsPrivate *priv = NM_SETTINGS_GET_PRIVATE (self);
	GError *first_error = NULL;
	GSList *iter;
	const char *uuid;

	uuid = nm_connection_get_uuid (new_connection);

	nm_assert (nm_utils_is_uuid (uuid));

	for (iter = priv->plugins; iter; iter = iter->next) {
		NMSettingsPlugin *plugin = NM_SETTINGS_PLUGIN (iter->data);
		gs_unref_object NMSettingsStorage *storage = NULL;
		gs_unref_object NMConnection *connection_to_add = NULL;
		gs_unref_object NMConnection *connection_to_add_cloned = NULL;
		NMConnection *connection_to_add_real = NULL;
		gs_free_error GError *add_error = NULL;
		gboolean success;
		const char *filename;

		if (in_memory) {
			if (plugin != (NMSettingsPlugin *) priv->keyfile_plugin)
				continue;
			success = nms_keyfile_plugin_add_connection (priv->keyfile_plugin,
			                                             new_connection,
			                                             TRUE,
			                                             &storage,
			                                             &connection_to_add,
			                                             &add_error);
		} else {
			success = nm_settings_plugin_add_connection (plugin,
			                                             new_connection,
			                                             &storage,
			                                             &connection_to_add,
			                                             &add_error);
		}
		if (!success) {
			_LOGT ("add-connection: failed to add %s/'%s': %s",
			       nm_connection_get_uuid (new_connection),
			       nm_connection_get_id (new_connection),
			       add_error->message);
			if (!first_error)
				first_error = g_steal_pointer (&add_error);
			continue;
		}

		if (nm_streq0 (nm_settings_storage_get_uuid (storage), uuid)) {
			gs_unref_variant GVariant *agent_owned_secrets = NULL;

			agent_owned_secrets = nm_connection_to_dbus (new_connection,
			                                               NM_CONNECTION_SERIALIZE_ONLY_SECRETS
			                                             | NM_CONNECTION_SERIALIZE_WITH_SECRETS_AGENT_OWNED);
			connection_to_add_real = _connection_changed_normalize_connection (storage,
			                                                                   connection_to_add,
			                                                                   agent_owned_secrets,
			                                                                   &connection_to_add_cloned);
		}
		if (!connection_to_add_real) {
			nm_assert_not_reached ();
			continue;
		}

		filename = nm_settings_storage_get_filename (storage);
		_LOGT ("add-connection: successfully added connection %s,'%s' ("NM_HASH_OBFUSCATE_PTR_FMT"%s%s%s",
		       nm_settings_storage_get_uuid (storage),
		       nm_connection_get_id (new_connection),
		       STORAGE_OBFUSCATE_PTR (storage),
		       NM_PRINT_FMT_QUOTED (filename, ", \"", filename, "\")", ")"));

		*out_new_storage = g_steal_pointer (&storage);
		*out_new_connection =    g_steal_pointer (&connection_to_add_cloned)
		                      ?: g_steal_pointer (&connection_to_add);
		nm_assert (NM_IS_CONNECTION (*out_new_connection));
		return TRUE;
	}

	nm_assert (first_error);
	g_propagate_error (error, first_error);
	return FALSE;
}

/**
 * nm_settings_add_connection:
 * @self: the #NMSettings object
 * @connection: the source connection to create a new #NMSettingsConnection from
 * @save_to_disk: %TRUE to save the connection to disk immediately, %FALSE to
 * not save to disk
 * @out_sett_conn: (allow-none) (transfer none): the added settings connection on success.
 * @error: on return, a location to store any errors that may occur
 *
 * Creates a new #NMSettingsConnection for the given source @connection.
 * The returned object is owned by @self and the caller must reference
 * the object to continue using it.
 *
 * Returns: TRUE on success.
 */
gboolean
nm_settings_add_connection (NMSettings *self,
                            NMConnection *connection,
                            gboolean save_to_disk,
                            NMSettingsConnection **out_sett_conn,
                            GError **error)
{
	NMSettingsPrivate *priv = NM_SETTINGS_GET_PRIVATE (self);
	gs_unref_object NMConnection *connection_cloned_1 = NULL;
	gs_unref_object NMConnection *new_connection = NULL;
	gs_unref_object NMSettingsStorage *storage = NULL;
	gs_free_error GError *local = NULL;
	const char *uuid;
	SettConnEntry *sett_conn_entry;
	gboolean to_delete;

	NM_SET_OUT (out_sett_conn, NULL);

	uuid = nm_connection_get_uuid (connection);

	/* Make sure a connection with this UUID doesn't already exist */
	if (_sett_conn_entry_get_conn (g_hash_table_lookup (priv->sett_conn_entries, &uuid))) {
		g_set_error_literal (error,
		                     NM_SETTINGS_ERROR,
		                     NM_SETTINGS_ERROR_UUID_EXISTS,
		                     "a connection with this UUID already exists");
		return FALSE;
	}

	if (!_nm_connection_ensure_normalized (connection,
	                                       FALSE,
	                                       NULL,
	                                       FALSE,
	                                       &connection_cloned_1,
	                                       &local)) {
		g_set_error (error,
		             NM_SETTINGS_ERROR,
		             NM_SETTINGS_ERROR_INVALID_CONNECTION,
		             "connection is invalid: %s",
		             local->message);
		return FALSE;
	}
	if (connection_cloned_1)
		connection = connection_cloned_1;

	if (!_add_connection_to_first_plugin (self,
	                                      connection,
	                                      !save_to_disk,
	                                      &storage,
	                                      &new_connection,
	                                      &local)) {
		g_set_error (error,
		             NM_SETTINGS_ERROR,
		             NM_SETTINGS_ERROR_FAILED,
		             "failure adding connection: %s",
		             local->message);
		return FALSE;
	}

	if (!_connection_changed_prepare (self,
	                                  storage,
	                                  new_connection,
	                                  TRUE,
	                                  &sett_conn_entry,
	                                  &to_delete))
		nm_assert_not_reached ();
	nm_assert (!to_delete);

	_connection_changed_update (self, sett_conn_entry, connection, TRUE);

	nm_assert (sett_conn_entry == g_hash_table_lookup (priv->sett_conn_entries, &uuid));

	NM_SET_OUT (out_sett_conn, _sett_conn_entry_get_conn (sett_conn_entry));
	return TRUE;
}

/*****************************************************************************/

gboolean
nm_settings_update_connection (NMSettings *self,
                               NMSettingsConnection *sett_conn,
                               NMConnection *connection,
                               gboolean in_memory,
                               gboolean remove_from_disk,
                               GError **error)
{
	NMSettingsPrivate *priv;
	gs_unref_object NMConnection *connection_cloned_1 = NULL;
	gs_unref_object NMConnection *new_connection_cloned = NULL;
	gs_unref_object NMConnection *new_connection = NULL;
	NMConnection *new_connection_real;
	gs_free_error GError *local = NULL;
	gs_unref_object NMSettingsStorage *cur_storage = NULL;
	gs_unref_object NMSettingsStorage *new_storage = NULL;
	SettConnEntry *sett_conn_entry;
	gboolean cur_in_memory;
	gboolean move_storage;
	gboolean to_delete;
	const char *uuid;
	gboolean success;

	g_return_val_if_fail (NM_IS_SETTING (self), FALSE);
	g_return_val_if_fail (NM_IS_SETTINGS_CONNECTION (sett_conn), FALSE);
	g_return_val_if_fail (!connection || NM_IS_CONNECTION (connection), FALSE);

	priv = NM_SETTINGS_GET_PRIVATE (self);

	cur_storage = g_object_ref (nm_settings_connection_get_storage (sett_conn));

	uuid = nm_settings_storage_get_uuid (cur_storage);

	nm_assert (NM_IS_SETTINGS_STORAGE (cur_storage));
	nm_assert (_sett_conn_entry_get_conn (g_hash_table_lookup (priv->sett_conn_entries, &uuid)) == sett_conn);

	if (connection) {
		if (!_nm_connection_ensure_normalized (connection,
		                                       FALSE,
		                                       uuid,
		                                       TRUE,
		                                       &connection_cloned_1,
		                                       &local)) {
			g_set_error (error,
			             NM_SETTINGS_ERROR,
			             NM_SETTINGS_ERROR_INVALID_CONNECTION,
			             "connection is invalid: %s",
			             local->message);
			return FALSE;
		}
		if (connection_cloned_1)
			connection = connection_cloned_1;
	} else
		connection = nm_settings_connection_get_connection (sett_conn);

	cur_in_memory = nm_settings_storage_is_in_memory (cur_storage);

	move_storage = ((!in_memory) != (!cur_in_memory));

	if (move_storage) {
		success = _add_connection_to_first_plugin (self,
		                                           connection,
		                                           in_memory,
		                                           &new_storage,
		                                           &new_connection,
		                                           &local);
	} else {
		success = nm_settings_plugin_update_connection (nm_settings_storage_get_plugin (cur_storage),
		                                                cur_storage,
		                                                connection,
		                                                &new_storage,
		                                                &new_connection,
		                                                &local);
	}
	if (!success) {
		g_set_error (error,
		             NM_SETTINGS_ERROR,
		             NM_SETTINGS_ERROR_INVALID_CONNECTION,
		             "failed to %s connection: %s",
		             move_storage ? "write" : "update",
		             local->message);
		return FALSE;
	}

	nm_assert_valid_settings_storage (NULL, new_storage);
	nm_assert (NM_IS_CONNECTION (new_connection));
	nm_assert (nm_streq (uuid, nm_settings_storage_get_uuid (new_storage)));

	if (move_storage)
		new_connection_real = new_connection;
	else {
		gs_unref_variant GVariant *agent_owned_secrets = NULL;

		agent_owned_secrets = nm_connection_to_dbus (connection,
		                                               NM_CONNECTION_SERIALIZE_ONLY_SECRETS
		                                             | NM_CONNECTION_SERIALIZE_WITH_SECRETS_AGENT_OWNED);
		new_connection_real = _connection_changed_normalize_connection (new_storage,
		                                                                new_connection,
		                                                                agent_owned_secrets,
		                                                                &new_connection_cloned);
	}

	nm_assert (NM_IS_CONNECTION (new_connection_real));

	if (!_connection_changed_prepare (self,
	                                  new_storage,
	                                  new_connection_real,
	                                  TRUE,
	                                  &sett_conn_entry,
	                                  &to_delete))
		g_return_val_if_reached (FALSE);
	if (to_delete)
		g_return_val_if_reached (FALSE);

	if (new_storage != cur_storage) {
		SettConnEntry *sett_conn_entry_old;

		if (!nm_settings_plugin_delete_connection (nm_settings_storage_get_plugin (cur_storage),
		                                           cur_storage,
		                                           remove_from_disk,
		                                           &local)) {
			_LOGW ("add-connection: failed to delete moved storage "NM_HASH_OBFUSCATE_PTR_FMT": %s",
			       STORAGE_OBFUSCATE_PTR (cur_storage),
			       local->message);
			g_clear_error (&local);
		}

		if (!_connection_changed_prepare (self,
		                                  cur_storage,
		                                  NULL,
		                                  FALSE,
		                                  &sett_conn_entry_old,
		                                  &to_delete))
			nm_assert_not_reached ();
		nm_assert (!sett_conn_entry_old);
	}

	_connection_changed_update (self, sett_conn_entry, connection, TRUE);

	return TRUE;
}

void
nm_settings_delete_connection (NMSettings *self,
                               NMSettingsConnection *sett_conn,
                               gboolean remove_from_disk)
{
	NMSettingsPrivate *priv;
	NMSettingsStorage *cur_storage;
	gs_free_error GError *local = NULL;
	SettConnEntry *sett_conn_entry = NULL;
	const char *uuid;

	g_return_if_fail (NM_IS_SETTING (self));
	g_return_if_fail (NM_IS_SETTINGS_CONNECTION (sett_conn));

	priv = NM_SETTINGS_GET_PRIVATE (self);

	cur_storage = nm_settings_connection_get_storage (sett_conn);

	nm_assert (NM_IS_SETTINGS_STORAGE (cur_storage));

	uuid = nm_settings_storage_get_uuid (cur_storage);
	nm_assert (nm_utils_is_uuid (uuid));

	sett_conn_entry = g_hash_table_lookup (priv->sett_conn_entries, &uuid);
	g_return_if_fail (sett_conn_entry);
	nm_assert (sett_conn_entry->sett_conn == sett_conn);
	nm_assert (sett_conn_entry->storage == cur_storage);

	if (!nm_settings_plugin_delete_connection (nm_settings_storage_get_plugin (cur_storage),
	                                           cur_storage,
	                                           remove_from_disk,
	                                           &local)) {
		_LOGW ("add-connection: failed to delete storage "NM_HASH_OBFUSCATE_PTR_FMT": %s",
		       STORAGE_OBFUSCATE_PTR (cur_storage),
		       local->message);
		g_clear_error (&local);
		/* there is no aborting back form this. We must get rid of the connection and
		 * cannot do better than warn. Proceed... */
	}

	_connection_changed_delete (self, sett_conn_entry);
}

/*****************************************************************************/

static void
send_agent_owned_secrets (NMSettings *self,
                          NMSettingsConnection *sett_conn,
                          NMAuthSubject *subject)
{
	NMSettingsPrivate *priv = NM_SETTINGS_GET_PRIVATE (self);
	gs_unref_object NMConnection *for_agent = NULL;

	/* Dupe the connection so we can clear out non-agent-owned secrets,
	 * as agent-owned secrets are the only ones we send back to be saved.
	 * Only send secrets to agents of the same UID that called update too.
	 */
	for_agent = nm_simple_connection_new_clone (nm_settings_connection_get_connection (sett_conn));
	_nm_connection_clear_secrets_by_secret_flags (for_agent,
	                                              NM_SETTING_SECRET_FLAG_AGENT_OWNED);
	nm_agent_manager_save_secrets (priv->agent_mgr,
	                               nm_dbus_object_get_path (NM_DBUS_OBJECT (sett_conn)),
	                               for_agent,
	                               subject);
}

static void
pk_add_cb (NMAuthChain *chain,
           GDBusMethodInvocation *context,
           gpointer user_data)
{
	NMSettings *self = NM_SETTINGS (user_data);
	NMAuthCallResult result;
	gs_free_error GError *error = NULL;
	NMConnection *connection = NULL;
	gs_unref_object NMSettingsConnection *added = NULL;
	NMSettingsAddCallback callback;
	gpointer callback_data;
	NMAuthSubject *subject;
	const char *perm;
	gboolean save_to_disk;

	nm_assert (G_IS_DBUS_METHOD_INVOCATION (context));

	c_list_unlink (nm_auth_chain_parent_lst_list (chain));

	perm = nm_auth_chain_get_data (chain, "perm");
	nm_assert (perm);

	result = nm_auth_chain_get_result (chain, perm);

	if (result != NM_AUTH_CALL_RESULT_YES) {
		error = g_error_new_literal (NM_SETTINGS_ERROR,
		                             NM_SETTINGS_ERROR_PERMISSION_DENIED,
		                             "Insufficient privileges.");
	} else {
		/* Authorized */
		connection = nm_auth_chain_get_data (chain, "connection");
		nm_assert (connection);

		save_to_disk = GPOINTER_TO_UINT (nm_auth_chain_get_data (chain, "save-to-disk"));

		nm_settings_add_connection (self, connection, save_to_disk, &added, &error);

		/* The callback may remove the connection from the settings manager (e.g.
		 * because it's found to be incompatible with the device on AddAndActivate).
		 * But we need to keep it alive for a bit longer, precisely to check wehther
		 * it's still known to the setting manager. */
		nm_g_object_ref (added);
	}

	callback = nm_auth_chain_get_data (chain, "callback");
	callback_data = nm_auth_chain_get_data (chain, "callback-data");
	subject = nm_auth_chain_get_data (chain, "subject");

	callback (self, added, error, context, subject, callback_data);

	/* Send agent-owned secrets to the agents */
	if (   added
	    && nm_settings_has_connection (self, added))
		send_agent_owned_secrets (self, added, subject);
}

void
nm_settings_add_connection_dbus (NMSettings *self,
                                 NMConnection *connection,
                                 gboolean save_to_disk,
                                 NMAuthSubject *subject,
                                 GDBusMethodInvocation *context,
                                 NMSettingsAddCallback callback,
                                 gpointer user_data)
{
	NMSettingsPrivate *priv = NM_SETTINGS_GET_PRIVATE (self);
	NMSettingConnection *s_con;
	NMAuthChain *chain;
	GError *error = NULL, *tmp_error = NULL;
	const char *perm;

	g_return_if_fail (NM_IS_CONNECTION (connection));
	g_return_if_fail (NM_IS_AUTH_SUBJECT (subject));
	g_return_if_fail (G_IS_DBUS_METHOD_INVOCATION (context));

	/* Connection must be valid, of course */
	if (!nm_connection_verify (connection, &tmp_error)) {
		error = g_error_new (NM_SETTINGS_ERROR,
		                     NM_SETTINGS_ERROR_INVALID_CONNECTION,
		                     "The connection was invalid: %s",
		                     tmp_error->message);
		g_error_free (tmp_error);
		goto done;
	}

	/* FIXME: The kernel doesn't support Ad-Hoc WPA connections well at this time,
	 * and turns them into open networks.  It's been this way since at least
	 * 2.6.30 or so; until that's fixed, disable WPA-protected Ad-Hoc networks.
	 */
	if (nm_utils_connection_is_adhoc_wpa (connection)) {
		error = g_error_new_literal (NM_SETTINGS_ERROR,
		                             NM_SETTINGS_ERROR_INVALID_CONNECTION,
		                             "WPA Ad-Hoc disabled due to kernel bugs");
		goto done;
	}

	if (!nm_auth_is_subject_in_acl_set_error (connection,
	                                          subject,
	                                          NM_SETTINGS_ERROR,
	                                          NM_SETTINGS_ERROR_PERMISSION_DENIED,
	                                          &error))
		goto done;

	/* If the caller is the only user in the connection's permissions, then
	 * we use the 'modify.own' permission instead of 'modify.system'.  If the
	 * request affects more than just the caller, require 'modify.system'.
	 */
	s_con = nm_connection_get_setting_connection (connection);
	nm_assert (s_con);
	if (nm_setting_connection_get_num_permissions (s_con) == 1)
		perm = NM_AUTH_PERMISSION_SETTINGS_MODIFY_OWN;
	else
		perm = NM_AUTH_PERMISSION_SETTINGS_MODIFY_SYSTEM;

	/* Validate the user request */
	chain = nm_auth_chain_new_subject (subject, context, pk_add_cb, self);
	if (!chain) {
		error = g_error_new_literal (NM_SETTINGS_ERROR,
		                             NM_SETTINGS_ERROR_PERMISSION_DENIED,
		                             "Unable to authenticate the request.");
		goto done;
	}

	c_list_link_tail (&priv->auth_lst_head, nm_auth_chain_parent_lst_list (chain));

	nm_auth_chain_set_data (chain, "perm", (gpointer) perm, NULL);
	nm_auth_chain_set_data (chain, "connection", g_object_ref (connection), g_object_unref);
	nm_auth_chain_set_data (chain, "callback", callback, NULL);
	nm_auth_chain_set_data (chain, "callback-data", user_data, NULL);
	nm_auth_chain_set_data (chain, "subject", g_object_ref (subject), g_object_unref);
	nm_auth_chain_set_data (chain, "save-to-disk", GUINT_TO_POINTER (save_to_disk), NULL);
	nm_auth_chain_add_call_unsafe (chain, perm, TRUE);
	return;

done:
	nm_assert (error);
	callback (self, NULL, error, context, subject, user_data);
	g_error_free (error);
}

static void
settings_add_connection_add_cb (NMSettings *self,
                                NMSettingsConnection *connection,
                                GError *error,
                                GDBusMethodInvocation *context,
                                NMAuthSubject *subject,
                                gpointer user_data)
{
	if (error) {
		g_dbus_method_invocation_return_gerror (context, error);
		nm_audit_log_connection_op (NM_AUDIT_OP_CONN_ADD, NULL, FALSE, NULL, subject, error->message);
	} else {
		g_dbus_method_invocation_return_value (context,
		                                       g_variant_new ("(o)",
		                                                      nm_dbus_object_get_path (NM_DBUS_OBJECT (connection))));
		nm_audit_log_connection_op (NM_AUDIT_OP_CONN_ADD, connection, TRUE, NULL,
		                            subject, NULL);
	}
}

static void
settings_add_connection_helper (NMSettings *self,
                                GDBusMethodInvocation *context,
                                GVariant *settings,
                                gboolean save_to_disk)
{
	gs_unref_object NMConnection *connection = NULL;
	GError *error = NULL;
	gs_unref_object NMAuthSubject *subject = NULL;

	connection = _nm_simple_connection_new_from_dbus (settings,
	                                                    NM_SETTING_PARSE_FLAGS_STRICT
	                                                  | NM_SETTING_PARSE_FLAGS_NORMALIZE,
	                                                  &error);

	if (   !connection
	    || !nm_connection_verify_secrets (connection, &error)) {
		g_dbus_method_invocation_take_error (context, error);
		return;
	}

	subject = nm_auth_subject_new_unix_process_from_context (context);
	if (!subject) {
		g_dbus_method_invocation_return_error_literal (context,
		                                               NM_SETTINGS_ERROR,
		                                               NM_SETTINGS_ERROR_PERMISSION_DENIED,
		                                               "Unable to determine UID of request.");
		return;
	}

	nm_settings_add_connection_dbus (self,
	                                 connection,
	                                 save_to_disk,
	                                 subject,
	                                 context,
	                                 settings_add_connection_add_cb,
	                                 NULL);
}

static void
impl_settings_add_connection (NMDBusObject *obj,
                              const NMDBusInterfaceInfoExtended *interface_info,
                              const NMDBusMethodInfoExtended *method_info,
                              GDBusConnection *connection,
                              const char *sender,
                              GDBusMethodInvocation *invocation,
                              GVariant *parameters)
{
	NMSettings *self = NM_SETTINGS (obj);
	gs_unref_variant GVariant *settings = NULL;

	g_variant_get (parameters, "(@a{sa{sv}})", &settings);
	settings_add_connection_helper (self, invocation, settings, TRUE);
}

static void
impl_settings_add_connection_unsaved (NMDBusObject *obj,
                                      const NMDBusInterfaceInfoExtended *interface_info,
                                      const NMDBusMethodInfoExtended *method_info,
                                      GDBusConnection *connection,
                                      const char *sender,
                                      GDBusMethodInvocation *invocation,
                                      GVariant *parameters)
{
	NMSettings *self = NM_SETTINGS (obj);
	gs_unref_variant GVariant *settings = NULL;

	g_variant_get (parameters, "(@a{sa{sv}})", &settings);
	settings_add_connection_helper (self, invocation, settings, FALSE);
}

/*****************************************************************************/

static void
impl_settings_load_connections (NMDBusObject *obj,
                                const NMDBusInterfaceInfoExtended *interface_info,
                                const NMDBusMethodInfoExtended *method_info,
                                GDBusConnection *dbus_connection,
                                const char *sender,
                                GDBusMethodInvocation *invocation,
                                GVariant *parameters)
{
	NMSettings *self = NM_SETTINGS (obj);
	NMSettingsPrivate *priv = NM_SETTINGS_GET_PRIVATE (self);
	gs_unref_ptrarray GPtrArray *failures = NULL;
	gs_free const char **filenames = NULL;

	g_variant_get (parameters, "(^a&s)", &filenames);

	/* The permission is already enforced by the D-Bus daemon, but we ensure
	 * that the caller is still alive so that clients are forced to wait and
	 * we'll be able to switch to polkit without breaking behavior.
	 */
	if (!nm_dbus_manager_ensure_uid (nm_dbus_object_get_manager (obj),
	                                 invocation,
	                                 G_MAXULONG,
	                                 NM_SETTINGS_ERROR,
	                                 NM_SETTINGS_ERROR_PERMISSION_DENIED))
		return;

	if (filenames) {
		gsize i;

		for (i = 0; filenames[i]; i++) {
			gboolean handled = FALSE;

			if (filenames[i][0] != '/')
				_LOGW ("load: connection filename '%s' is not an absolute path", filenames[i]);
			else {
				GSList *iter;

				for (iter = priv->plugins; iter; iter = iter->next) {
					NMSettingsPlugin *plugin = iter->data;
					gs_unref_object NMSettingsStorage *storage = NULL;
					gs_unref_ptrarray GPtrArray *replaced_storages = NULL;
					gs_unref_object NMConnection *connection_added = NULL;
					gs_unref_object NMConnection *connection_cloned = NULL;
					NMConnection *connection;
					SettConnEntry *sett_conn_entry;
					gboolean to_delete;

					if (!nm_settings_plugin_load_connection (plugin,
					                                         filenames[i],
					                                         &storage,
					                                         &connection_added,
					                                         &replaced_storages,
					                                         NULL))
						continue;

					if (storage) {
						connection = _connection_changed_normalize_connection (storage,
						                                                       connection_added,
						                                                       NULL,
						                                                       &connection_cloned);
						if (_connection_changed_prepare (self,
						                                 storage,
						                                 connection,
						                                 TRUE,
						                                 &sett_conn_entry,
						                                 &to_delete)) {
							if (to_delete)
								_connection_changed_delete (self, sett_conn_entry);
							else
								_connection_changed_update (self, sett_conn_entry, connection, TRUE);
						}
					}
					if (replaced_storages) {
						guint j;

						for (j = 0; j < replaced_storages->len; j++) {
							if (_connection_changed_prepare (self,
							                                 replaced_storages->pdata[j],
							                                 NULL,
							                                 TRUE,
							                                 &sett_conn_entry,
							                                 &to_delete)) {
								nm_assert (to_delete);
								_connection_changed_delete (self, sett_conn_entry);
							}
						}
					}

					handled = TRUE;
					break;
				}
			}

			if (!handled) {
				if (!failures)
					failures = g_ptr_array_new ();
				g_ptr_array_add (failures, (char *) filenames[i]);
			}
		}
	}

	if (failures)
		g_ptr_array_add (failures, NULL);

	g_dbus_method_invocation_return_value (invocation,
	                                       g_variant_new ("(b^as)",
	                                                      (gboolean) (!failures),
	                                                      failures
	                                                        ? (const char **) failures->pdata
	                                                        : NM_PTRARRAY_EMPTY (const char *)));
}

static void
impl_settings_reload_connections (NMDBusObject *obj,
                                  const NMDBusInterfaceInfoExtended *interface_info,
                                  const NMDBusMethodInfoExtended *method_info,
                                  GDBusConnection *connection,
                                  const char *sender,
                                  GDBusMethodInvocation *invocation,
                                  GVariant *parameters)
{
	NMSettings *self = NM_SETTINGS (obj);
	NMSettingsPrivate *priv = NM_SETTINGS_GET_PRIVATE (self);
	GSList *iter;

	/* The permission is already enforced by the D-Bus daemon, but we ensure
	 * that the caller is still alive so that clients are forced to wait and
	 * we'll be able to switch to polkit without breaking behavior.
	 */
	if (!nm_dbus_manager_ensure_uid (nm_dbus_object_get_manager (obj),
	                                 invocation,
	                                 G_MAXULONG,
	                                 NM_SETTINGS_ERROR,
	                                 NM_SETTINGS_ERROR_PERMISSION_DENIED))
		return;

	for (iter = priv->plugins; iter; iter = iter->next) {
		nm_settings_plugin_reload_connections (iter->data,
		                                       _plugin_reload_connections_cb,
		                                       self);
	}

	g_dbus_method_invocation_return_value (invocation, g_variant_new ("(b)", TRUE));
}

/*****************************************************************************/

static void
_clear_connections_cached_list (NMSettingsPrivate *priv)
{
	if (!priv->connections_cached_list)
		return;

	nm_assert (priv->connections_len == NM_PTRARRAY_LEN (priv->connections_cached_list));

#if NM_MORE_ASSERTS
	/* set the pointer to a bogus value. This makes it more apparent
	 * if somebody has a reference to the cached list and still uses
	 * it. That is a bug, this code just tries to make it blow up
	 * more eagerly. */
	memset (priv->connections_cached_list,
	        0xdeaddead,
	        sizeof (NMSettingsConnection *) * (priv->connections_len + 1));
#endif

	nm_clear_g_free (&priv->connections_cached_list);
}

static void
impl_settings_list_connections (NMDBusObject *obj,
                                const NMDBusInterfaceInfoExtended *interface_info,
                                const NMDBusMethodInfoExtended *method_info,
                                GDBusConnection *dbus_connection,
                                const char *sender,
                                GDBusMethodInvocation *invocation,
                                GVariant *parameters)
{
	NMSettings *self = NM_SETTINGS (obj);
	NMSettingsPrivate *priv = NM_SETTINGS_GET_PRIVATE (self);
	gs_free const char **strv = NULL;

	strv = nm_dbus_utils_get_paths_for_clist (&priv->connections_lst_head,
	                                          priv->connections_len,
	                                          G_STRUCT_OFFSET (NMSettingsConnection, _connections_lst),
	                                          TRUE);
	g_dbus_method_invocation_return_value (invocation,
	                                       g_variant_new ("(^ao)", strv));
}

NMSettingsConnection *
nm_settings_get_connection_by_uuid (NMSettings *self, const char *uuid)
{
	NMSettingsPrivate *priv;

	g_return_val_if_fail (NM_IS_SETTINGS (self), NULL);
	g_return_val_if_fail (uuid != NULL, NULL);

	priv = NM_SETTINGS_GET_PRIVATE (self);

	return _sett_conn_entry_get_conn (g_hash_table_lookup (priv->sett_conn_entries, &uuid));
}

static void
impl_settings_get_connection_by_uuid (NMDBusObject *obj,
                                      const NMDBusInterfaceInfoExtended *interface_info,
                                      const NMDBusMethodInfoExtended *method_info,
                                      GDBusConnection *dbus_connection,
                                      const char *sender,
                                      GDBusMethodInvocation *invocation,
                                      GVariant *parameters)
{
	NMSettings *self = NM_SETTINGS (obj);
	NMSettingsConnection *sett_conn;
	gs_unref_object NMAuthSubject *subject = NULL;
	GError *error = NULL;
	const char *uuid;

	g_variant_get (parameters, "(&s)", &uuid);

	sett_conn = nm_settings_get_connection_by_uuid (self, uuid);
	if (!sett_conn) {
		error = g_error_new_literal (NM_SETTINGS_ERROR,
		                             NM_SETTINGS_ERROR_INVALID_CONNECTION,
		                             "No connection with the UUID was found.");
		goto error;
	}

	subject = nm_auth_subject_new_unix_process_from_context (invocation);
	if (!subject) {
		error = g_error_new_literal (NM_SETTINGS_ERROR,
		                             NM_SETTINGS_ERROR_PERMISSION_DENIED,
		                             "Unable to determine UID of request.");
		goto error;
	}

	if (!nm_auth_is_subject_in_acl_set_error (nm_settings_connection_get_connection (sett_conn),
	                                          subject,
	                                          NM_SETTINGS_ERROR,
	                                          NM_SETTINGS_ERROR_PERMISSION_DENIED,
	                                          &error))
		goto error;

	g_dbus_method_invocation_return_value (invocation,
	                                       g_variant_new ("(o)",
	                                                      nm_dbus_object_get_path (NM_DBUS_OBJECT (sett_conn))));
	return;

error:
	g_dbus_method_invocation_take_error (invocation, error);
}

/**
 * nm_settings_get_connections:
 * @self: the #NMSettings
 * @out_len: (out) (allow-none): returns the number of returned
 *   connections.
 *
 * Returns: (transfer none): a list of NMSettingsConnections. The list is
 * unsorted and NULL terminated. The result is never %NULL, in case of no
 * connections, it returns an empty list.
 * The returned list is cached internally, only valid until the next
 * NMSettings operation.
 */
NMSettingsConnection *const*
nm_settings_get_connections (NMSettings *self, guint *out_len)
{
	NMSettingsPrivate *priv;
	NMSettingsConnection **v;
	NMSettingsConnection *con;
	guint i;

	g_return_val_if_fail (NM_IS_SETTINGS (self), NULL);

	priv = NM_SETTINGS_GET_PRIVATE (self);

	nm_assert (priv->connections_len == c_list_length (&priv->connections_lst_head));

	if (G_UNLIKELY (!priv->connections_cached_list)) {
		v = g_new (NMSettingsConnection *, priv->connections_len + 1);

		i = 0;
		c_list_for_each_entry (con, &priv->connections_lst_head, _connections_lst) {
			nm_assert (i < priv->connections_len);
			v[i++] = con;
		}
		nm_assert (i == priv->connections_len);
		v[i] = NULL;

		priv->connections_cached_list = v;
	}

	NM_SET_OUT (out_len, priv->connections_len);
	return priv->connections_cached_list;
}

/**
 * nm_settings_get_connections_clone:
 * @self: the #NMSetting
 * @out_len: (allow-none): optional output argument
 * @func: caller-supplied function for filtering connections
 * @func_data: caller-supplied data passed to @func
 * @sort_compare_func: (allow-none): optional function pointer for
 *   sorting the returned list.
 * @sort_data: user data for @sort_compare_func.
 *
 * Returns: (transfer container) (element-type NMSettingsConnection):
 *   an NULL terminated array of #NMSettingsConnection objects that were
 *   filtered by @func (or all connections if no filter was specified).
 *   The order is arbitrary.
 *   Caller is responsible for freeing the returned array with free(),
 *   the contained values do not need to be unrefed.
 */
NMSettingsConnection **
nm_settings_get_connections_clone (NMSettings *self,
                                   guint *out_len,
                                   NMSettingsConnectionFilterFunc func,
                                   gpointer func_data,
                                   GCompareDataFunc sort_compare_func,
                                   gpointer sort_data)
{
	NMSettingsConnection *const*list_cached;
	NMSettingsConnection **list;
	guint len, i, j;

	g_return_val_if_fail (NM_IS_SETTINGS (self), NULL);

	list_cached = nm_settings_get_connections (self, &len);

#if NM_MORE_ASSERTS
	nm_assert (list_cached);
	for (i = 0; i < len; i++)
		nm_assert (NM_IS_SETTINGS_CONNECTION (list_cached[i]));
	nm_assert (!list_cached[i]);
#endif

	list = g_new (NMSettingsConnection *, ((gsize) len + 1));
	if (func) {
		for (i = 0, j = 0; i < len; i++) {
			if (func (self, list_cached[i], func_data))
				list[j++] = list_cached[i];
		}
		list[j] = NULL;
		len = j;
	} else
		memcpy (list, list_cached, sizeof (list[0]) * ((gsize) len + 1));

	if (   len > 1
	    && sort_compare_func) {
		g_qsort_with_data (list, len, sizeof (NMSettingsConnection *),
		                   sort_compare_func, sort_data);
	}
	NM_SET_OUT (out_len, len);
	return list;
}

NMSettingsConnection *
nm_settings_get_connection_by_path (NMSettings *self, const char *path)
{
	NMSettingsPrivate *priv;
	NMSettingsConnection *connection;

	g_return_val_if_fail (NM_IS_SETTINGS (self), NULL);
	g_return_val_if_fail (path, NULL);

	priv = NM_SETTINGS_GET_PRIVATE (self);

	connection = nm_dbus_manager_lookup_object (nm_dbus_object_get_manager (NM_DBUS_OBJECT (self)),
	                                            path);
	if (   !connection
	    || !NM_IS_SETTINGS_CONNECTION (connection))
		return NULL;

	nm_assert (c_list_contains (&priv->connections_lst_head, &connection->_connections_lst));
	return connection;
}

gboolean
nm_settings_has_connection (NMSettings *self, NMSettingsConnection *connection)
{
	gboolean has;

	g_return_val_if_fail (NM_IS_SETTINGS (self), FALSE);
	g_return_val_if_fail (NM_IS_SETTINGS_CONNECTION (connection), FALSE);

	has = !c_list_is_empty (&connection->_connections_lst);

	nm_assert (has == nm_c_list_contains_entry (&NM_SETTINGS_GET_PRIVATE (self)->connections_lst_head,
                                                connection,
                                                _connections_lst));
	nm_assert (({
		NMSettingsConnection *candidate = NULL;
		const char *path;

		path = nm_dbus_object_get_path (NM_DBUS_OBJECT (connection));
		if (path)
			candidate = nm_settings_get_connection_by_path (self, path);

		(has == (connection == candidate));
	}));

	return has;
}

/*****************************************************************************/

static void
add_plugin (NMSettings *self,
            NMSettingsPlugin *plugin,
            const char *pname,
            const char *path)
{
	NMSettingsPrivate *priv;

	nm_assert (NM_IS_SETTINGS (self));
	nm_assert (NM_IS_SETTINGS_PLUGIN (plugin));

	priv = NM_SETTINGS_GET_PRIVATE (self);

	nm_assert (!g_slist_find (priv->plugins, plugin));

	priv->plugins = g_slist_append (priv->plugins, g_object_ref (plugin));

	_LOGI ("Loaded settings plugin: %s (%s%s%s)",
	       pname,
	       NM_PRINT_FMT_QUOTED (path, "\"", path, "\"", "internal"));
}

static gboolean
add_plugin_load_file (NMSettings *self, const char *pname, GError **error)
{
	gs_free char *full_name = NULL;
	gs_free char *path = NULL;
	gs_unref_object NMSettingsPlugin *plugin = NULL;
	GModule *module;
	NMSettingsPluginFactoryFunc factory_func;
	struct stat st;
	int errsv;

	full_name = g_strdup_printf ("nm-settings-plugin-%s", pname);
	path = g_module_build_path (NMPLUGINDIR, full_name);

	if (stat (path, &st) != 0) {
		errsv = errno;
		_LOGW ("could not load plugin '%s' from file '%s': %s", pname, path, nm_strerror_native (errsv));
		return TRUE;
	}
	if (!S_ISREG (st.st_mode)) {
		_LOGW ("could not load plugin '%s' from file '%s': not a file", pname, path);
		return TRUE;
	}
	if (st.st_uid != 0) {
		_LOGW ("could not load plugin '%s' from file '%s': file must be owned by root", pname, path);
		return TRUE;
	}
	if (st.st_mode & (S_IWGRP | S_IWOTH | S_ISUID)) {
		_LOGW ("could not load plugin '%s' from file '%s': invalid file permissions", pname, path);
		return TRUE;
	}

	module = g_module_open (path, G_MODULE_BIND_LOCAL);
	if (!module) {
		_LOGW ("could not load plugin '%s' from file '%s': %s",
		     pname, path, g_module_error ());
		return TRUE;
	}

	/* errors after this point are fatal, because we loaded the shared library already. */

	if (!g_module_symbol (module, "nm_settings_plugin_factory", (gpointer) (&factory_func))) {
		g_set_error (error, NM_SETTINGS_ERROR, NM_SETTINGS_ERROR_FAILED,
		             "Could not find plugin '%s' factory function.",
		             pname);
		g_module_close (module);
		return FALSE;
	}

	/* after accessing the plugin we cannot unload it anymore, because the glib
	 * types cannot be properly unregistered. */
	g_module_make_resident (module);

	plugin = (*factory_func) ();
	if (!NM_IS_SETTINGS_PLUGIN (plugin)) {
		g_set_error (error, NM_SETTINGS_ERROR, NM_SETTINGS_ERROR_FAILED,
		             "plugin '%s' returned invalid settings plugin",
		             pname);
		return FALSE;
	}

	add_plugin (self, NM_SETTINGS_PLUGIN (plugin), pname, path);
	return TRUE;
}

static void
add_plugin_keyfile (NMSettings *self)
{
	NMSettingsPrivate *priv = NM_SETTINGS_GET_PRIVATE (self);

	if (priv->keyfile_plugin)
		return;
	priv->keyfile_plugin = nms_keyfile_plugin_new ();
	add_plugin (self, NM_SETTINGS_PLUGIN (priv->keyfile_plugin), "keyfile", NULL);
}

static gboolean
load_plugins (NMSettings *self, const char *const*plugins, GError **error)
{
	const char *const*iter;
	gboolean success = TRUE;
	gboolean add_ibft = FALSE;
	gboolean has_no_ibft;
	gssize idx_no_ibft, idx_ibft;

	idx_ibft    = nm_utils_strv_find_first ((char **) plugins, -1, "ibft");
	idx_no_ibft = nm_utils_strv_find_first ((char **) plugins, -1, "no-ibft");
	has_no_ibft = idx_no_ibft >= 0 && idx_no_ibft > idx_ibft;
#if WITH_SETTINGS_PLUGIN_IBFT
	add_ibft = idx_no_ibft < 0 && idx_ibft < 0;
#endif

	for (iter = plugins; iter && *iter; iter++) {
		const char *pname = *iter;

		if (!*pname || strchr (pname, '/')) {
			_LOGW ("ignore invalid plugin \"%s\"", pname);
			continue;
		}

		if (NM_IN_STRSET (pname, "ifcfg-suse", "ifnet")) {
			_LOGW ("skipping deprecated plugin %s", pname);
			continue;
		}

		if (nm_streq (pname, "no-ibft"))
			continue;
		if (has_no_ibft && nm_streq (pname, "ibft"))
			continue;

		/* keyfile plugin is built-in now */
		if (nm_streq (pname, "keyfile")) {
			add_plugin_keyfile (self);
			continue;
		}

		if (nm_utils_strv_find_first ((char **) plugins,
		                              iter - plugins,
		                              pname) >= 0) {
			/* the plugin is already mentioned in the list previously.
			 * Don't load a duplicate. */
			continue;
		}

		success = add_plugin_load_file (self, pname, error);
		if (!success)
			break;

		if (   add_ibft
		    && nm_streq (pname, "ifcfg-rh")) {
			/* The plugin ibft is not explicitly mentioned but we just enabled "ifcfg-rh".
			 * Enable "ibft" by default after "ifcfg-rh". */
			add_ibft = FALSE;
			success = add_plugin_load_file (self, "ibft", error);
			if (!success)
				break;
		}
	}

	/* If keyfile plugin was not among configured plugins, add it as the last one */
	if (success)
		add_plugin_keyfile (self);

	return success;
}

/*****************************************************************************/

static void
pk_hostname_cb (NMAuthChain *chain,
                GDBusMethodInvocation *context,
                gpointer user_data)
{
	NMSettings *self = NM_SETTINGS (user_data);
	NMSettingsPrivate *priv = NM_SETTINGS_GET_PRIVATE (self);
	NMAuthCallResult result;
	GError *error = NULL;
	const char *hostname;

	nm_assert (G_IS_DBUS_METHOD_INVOCATION (context));

	c_list_unlink (nm_auth_chain_parent_lst_list (chain));

	result = nm_auth_chain_get_result (chain, NM_AUTH_PERMISSION_SETTINGS_MODIFY_HOSTNAME);

	/* If our NMSettingsConnection is already gone, do nothing */
	if (result != NM_AUTH_CALL_RESULT_YES) {
		error = g_error_new_literal (NM_SETTINGS_ERROR,
		                             NM_SETTINGS_ERROR_PERMISSION_DENIED,
		                             "Insufficient privileges.");
	} else {
		hostname = nm_auth_chain_get_data (chain, "hostname");

		if (!nm_hostname_manager_write_hostname (priv->hostname_manager, hostname)) {
			error = g_error_new_literal (NM_SETTINGS_ERROR,
			                             NM_SETTINGS_ERROR_FAILED,
			                             "Saving the hostname failed.");
		}
	}

	if (error)
		g_dbus_method_invocation_take_error (context, error);
	else
		g_dbus_method_invocation_return_value (context, NULL);
}

static void
impl_settings_save_hostname (NMDBusObject *obj,
                             const NMDBusInterfaceInfoExtended *interface_info,
                             const NMDBusMethodInfoExtended *method_info,
                             GDBusConnection *connection,
                             const char *sender,
                             GDBusMethodInvocation *invocation,
                             GVariant *parameters)
{
	NMSettings *self = NM_SETTINGS (obj);
	NMSettingsPrivate *priv = NM_SETTINGS_GET_PRIVATE (self);
	NMAuthChain *chain;
	const char *hostname;

	g_variant_get (parameters, "(&s)", &hostname);

	/* Minimal validation of the hostname */
	if (!nm_hostname_manager_validate_hostname (hostname)) {
		g_dbus_method_invocation_return_error_literal (invocation,
		                                               NM_SETTINGS_ERROR,
		                                               NM_SETTINGS_ERROR_INVALID_HOSTNAME,
		                                               "The hostname was too long or contained invalid characters.");
		return;
	}

	chain = nm_auth_chain_new_context (invocation, pk_hostname_cb, self);
	if (!chain) {
		g_dbus_method_invocation_return_error_literal (invocation,
		                                               NM_SETTINGS_ERROR,
		                                               NM_SETTINGS_ERROR_PERMISSION_DENIED,
		                                               "Unable to authenticate the request.");
		return;
	}

	c_list_link_tail (&priv->auth_lst_head, nm_auth_chain_parent_lst_list (chain));
	nm_auth_chain_add_call (chain, NM_AUTH_PERMISSION_SETTINGS_MODIFY_HOSTNAME, TRUE);
	nm_auth_chain_set_data (chain, "hostname", g_strdup (hostname), g_free);
}

/*****************************************************************************/

static void
_hostname_changed_cb (NMHostnameManager *hostname_manager,
                      GParamSpec *pspec,
                      gpointer user_data)
{
	_notify (user_data, PROP_HOSTNAME);
}

/*****************************************************************************/

static gboolean
have_connection_for_device (NMSettings *self, NMDevice *device)
{
	NMSettingsPrivate *priv = NM_SETTINGS_GET_PRIVATE (self);
	NMSettingWired *s_wired;
	const char *setting_hwaddr;
	const char *perm_hw_addr;
	NMSettingsConnection *sett_conn;

	g_return_val_if_fail (NM_IS_SETTINGS (self), FALSE);

	perm_hw_addr = nm_device_get_permanent_hw_address (device);

	/* Find a wired connection locked to the given MAC address, if any */
	c_list_for_each_entry (sett_conn, &priv->connections_lst_head, _connections_lst) {
		NMConnection *connection = nm_settings_connection_get_connection (sett_conn);
		NMSettingConnection *s_con = nm_connection_get_setting_connection (connection);
		const char *ctype;
		const char *iface;

		ctype = nm_setting_connection_get_connection_type (s_con);
		if (!NM_IN_STRSET (ctype, NM_SETTING_WIRED_SETTING_NAME,
		                          NM_SETTING_PPPOE_SETTING_NAME))
			continue;

		if (!nm_device_check_connection_compatible (device, connection, NULL))
			continue;

		iface = nm_setting_connection_get_interface_name (s_con);
		if (nm_streq0 (iface, nm_device_get_iface (device)))
			continue;

		s_wired = nm_connection_get_setting_wired (connection);
		if (   !s_wired
		    && nm_streq (ctype, NM_SETTING_PPPOE_SETTING_NAME)) {
			/* No wired setting; therefore the PPPoE connection applies to any device */
			return TRUE;
		}

		setting_hwaddr = nm_setting_wired_get_mac_address (s_wired);
		if (setting_hwaddr) {
			/* A connection mac-locked to this device */
			if (   perm_hw_addr
			    && nm_utils_hwaddr_matches (setting_hwaddr, -1, perm_hw_addr, -1))
				return TRUE;
		} else {
			/* A connection that applies to any wired device */
			return TRUE;
		}
	}

	/* See if there's a known non-NetworkManager configuration for the device */
	if (nm_device_spec_match_list (device, priv->unrecognized_specs))
		return TRUE;

	return FALSE;
}

static void
default_wired_connection_updated_by_user_cb (NMSettingsConnection *connection, gboolean by_user, NMSettings *self)
{
	NMDevice *device;

	if (!by_user)
		return;

	/* The connection has been changed by the user, it should no longer be
	 * considered a default wired connection, and should no longer affect
	 * the no-auto-default configuration option.
	 */
	device = g_object_get_qdata (G_OBJECT (connection), _default_wired_device_quark ());
	if (device)
		default_wired_clear_tag (self, device, connection, FALSE);
}

static void
default_wired_clear_tag (NMSettings *self,
                         NMDevice *device,
                         NMSettingsConnection *connection,
                         gboolean add_to_no_auto_default)
{
	nm_assert (NM_IS_SETTINGS (self));
	nm_assert (NM_IS_DEVICE (device));
	nm_assert (NM_IS_SETTINGS_CONNECTION (connection));
	nm_assert (device == g_object_get_qdata (G_OBJECT (connection), _default_wired_device_quark ()));
	nm_assert (connection == g_object_get_qdata (G_OBJECT (device), _default_wired_connection_quark ()));

	g_object_set_qdata (G_OBJECT (connection), _default_wired_device_quark (), NULL);
	g_object_set_qdata (G_OBJECT (device), _default_wired_connection_quark (), NULL);

	g_signal_handlers_disconnect_by_func (connection, G_CALLBACK (default_wired_connection_updated_by_user_cb), self);

	if (add_to_no_auto_default)
		nm_config_set_no_auto_default_for_device (NM_SETTINGS_GET_PRIVATE (self)->config, device);
}

static void
device_realized (NMDevice *device, GParamSpec *pspec, NMSettings *self)
{
	NMConnection *connection;
	NMSettingsConnection *added;
	GError *error = NULL;

	if (!nm_device_is_real (device))
		return;

	g_signal_handlers_disconnect_by_func (device,
	                                      G_CALLBACK (device_realized),
	                                      self);

	/* If the device isn't managed or it already has a default wired connection,
	 * ignore it.
	 */
	if (   !nm_device_get_managed (device, FALSE)
	    || g_object_get_qdata (G_OBJECT (device), _default_wired_connection_quark ())
	    || have_connection_for_device (self, device))
		return;

	connection = nm_device_new_default_connection (device);
	if (!connection)
		return;

	nm_settings_add_connection (self, connection, FALSE, &added, &error);

	g_object_unref (connection);

	if (!added) {
		if (!g_error_matches (error, NM_SETTINGS_ERROR, NM_SETTINGS_ERROR_UUID_EXISTS)) {
			_LOGW ("(%s) couldn't create default wired connection: %s",
			       nm_device_get_iface (device),
			       error->message);
		}
		g_clear_error (&error);
		return;
	}

	g_object_set_qdata (G_OBJECT (added), _default_wired_device_quark (), device);
	g_object_set_qdata (G_OBJECT (device), _default_wired_connection_quark (), added);

	g_signal_connect (added, NM_SETTINGS_CONNECTION_UPDATED_INTERNAL,
	                  G_CALLBACK (default_wired_connection_updated_by_user_cb), self);

	_LOGI ("(%s): created default wired connection '%s'",
	       nm_device_get_iface (device),
	       nm_settings_connection_get_id (added));
}

void
nm_settings_device_added (NMSettings *self, NMDevice *device)
{
	if (nm_device_is_real (device))
		device_realized (device, NULL, self);
	else {
		g_signal_connect_after (device, "notify::" NM_DEVICE_REAL,
		                        G_CALLBACK (device_realized),
		                        self);
	}
}

void
nm_settings_device_removed (NMSettings *self, NMDevice *device, gboolean quitting)
{
	NMSettingsConnection *connection;

	g_signal_handlers_disconnect_by_func (device,
	                                      G_CALLBACK (device_realized),
	                                      self);

	connection = g_object_get_qdata (G_OBJECT (device), _default_wired_connection_quark ());
	if (connection) {
		default_wired_clear_tag (self, device, connection, FALSE);

		/* Don't delete the default wired connection on shutdown, so that it
		 * remains up and can be assumed if NM starts again.
		 */
		if (quitting == FALSE)
			nm_settings_connection_delete (connection);
	}
}

/*****************************************************************************/

static void
session_monitor_changed_cb (NMSessionMonitor *session_monitor,
                            NMSettings *self)
{
	NMSettingsPrivate *priv = NM_SETTINGS_GET_PRIVATE (self);
	NMSettingsConnection *const*list;
	guint i, len;
	guint generation;

again:
	list = nm_settings_get_connections (self, &len);
	generation = priv->connections_generation;
	for (i = 0; i < len; i++) {
		nm_settings_connection_recheck_visibility (list[i],
		                                           session_monitor);
		if (generation != priv->connections_generation) {
			/* the cached list was invalidated. Start again.
			 *
			 * Note that nm_settings_connection_recheck_visibility() will do nothing
			 * if the visibility didn't change (including emitting no signals,
			 * and not invalidating the list).
			 *
			 * Hence, for this to be an endless loop, the settings would have
			 * to constantly change the visibility flag and also invalidate the list. */
			goto again;
		}
	}
}

/*****************************************************************************/

G_GNUC_PRINTF (4, 5)
static void
_kf_db_log_fcn (NMKeyFileDB *kf_db,
                int syslog_level,
                gpointer user_data,
                const char *fmt,
                ...)
{
	NMSettings *self = user_data;
	NMLogLevel level = nm_log_level_from_syslog (syslog_level);

	if (_NMLOG_ENABLED (level)) {
		NMSettingsPrivate *priv = NM_SETTINGS_GET_PRIVATE (self);
		gs_free char *msg = NULL;
		va_list ap;
		const char *prefix;

		va_start (ap, fmt);
		msg = g_strdup_vprintf (fmt, ap);
		va_end (ap);

		if (priv->kf_db_timestamps == kf_db)
			prefix = "timestamps";
		else if (priv->kf_db_seen_bssids == kf_db)
			prefix = "seen-bssids";
		else {
			nm_assert_not_reached ();
			prefix = "???";
		}

		_NMLOG (level, "[%s-keyfile]: %s", prefix, msg);
	}
}

static gboolean
_kf_db_got_dirty_flush (NMSettings *self,
                        gboolean is_timestamps)
{
	NMSettingsPrivate *priv = NM_SETTINGS_GET_PRIVATE (self);
	const char *prefix;
	NMKeyFileDB *kf_db;

	if (is_timestamps) {
		prefix = "timestamps";
		kf_db = priv->kf_db_timestamps;
		priv->kf_db_flush_idle_id_timestamps = 0;
	} else {
		prefix = "seen-bssids";
		kf_db = priv->kf_db_seen_bssids;
		priv->kf_db_flush_idle_id_seen_bssids = 0;
	}

	if (nm_key_file_db_is_dirty (kf_db))
		nm_key_file_db_to_file (kf_db, FALSE);
	else {
		_LOGT ("[%s-keyfile]: skip saving changes to \"%s\"",
		       prefix,
		       nm_key_file_db_get_filename (kf_db));
	}

	return G_SOURCE_REMOVE;
}

static gboolean
_kf_db_got_dirty_flush_timestamps_cb (gpointer user_data)
{
	return _kf_db_got_dirty_flush (user_data,
	                               TRUE);
}

static gboolean
_kf_db_got_dirty_flush_seen_bssids_cb (gpointer user_data)
{
	return _kf_db_got_dirty_flush (user_data,
	                               FALSE);
}

static void
_kf_db_got_dirty_fcn (NMKeyFileDB *kf_db,
                      gpointer user_data)
{
	NMSettings *self = user_data;
	NMSettingsPrivate *priv = NM_SETTINGS_GET_PRIVATE (self);
	GSourceFunc idle_func;
	guint *p_id;
	const char *prefix;

	if (priv->kf_db_timestamps == kf_db) {
		prefix = "timestamps";
		p_id = &priv->kf_db_flush_idle_id_timestamps;
		idle_func = _kf_db_got_dirty_flush_timestamps_cb;
	} else if (priv->kf_db_seen_bssids == kf_db) {
		prefix = "seen-bssids";
		p_id = &priv->kf_db_flush_idle_id_seen_bssids;
		idle_func = _kf_db_got_dirty_flush_seen_bssids_cb;
	} else {
		nm_assert_not_reached ();
		return;
	}

	if (*p_id != 0)
		return;
	_LOGT ("[%s-keyfile]: schedule flushing changes to disk", prefix);
	*p_id = g_idle_add_full (G_PRIORITY_LOW, idle_func, self, NULL);
}

void
nm_settings_kf_db_write (NMSettings *self)
{
	NMSettingsPrivate *priv;

	g_return_if_fail (NM_IS_SETTINGS (self));

	priv = NM_SETTINGS_GET_PRIVATE (self);
	if (priv->kf_db_timestamps)
		nm_key_file_db_to_file (priv->kf_db_timestamps, TRUE);
	if (priv->kf_db_seen_bssids)
		nm_key_file_db_to_file (priv->kf_db_seen_bssids, TRUE);
}

/*****************************************************************************/

gboolean
nm_settings_start (NMSettings *self, GError **error)
{
	NMSettingsPrivate *priv;
	gs_strfreev char **plugins = NULL;
	GSList *iter;

	priv = NM_SETTINGS_GET_PRIVATE (self);

	priv->hostname_manager = g_object_ref (nm_hostname_manager_get ());

	priv->kf_db_timestamps = nm_key_file_db_new (NMSTATEDIR "/timestamps",
	                                             "timestamps",
	                                             _kf_db_log_fcn,
	                                             _kf_db_got_dirty_fcn,
	                                             self);
	priv->kf_db_seen_bssids = nm_key_file_db_new (NMSTATEDIR "/seen-bssids",
	                                              "seen-bssids",
	                                              _kf_db_log_fcn,
	                                              _kf_db_got_dirty_fcn,
	                                              self);
	nm_key_file_db_start (priv->kf_db_timestamps);
	nm_key_file_db_start (priv->kf_db_seen_bssids);

	/* Load the plugins; fail if a plugin is not found. */
	plugins = nm_config_data_get_plugins (nm_config_get_data_orig (priv->config), TRUE);

	if (!load_plugins (self, (const char *const*) plugins, error))
		return FALSE;

	for (iter = priv->plugins; iter; iter = iter->next) {
		NMSettingsPlugin *plugin = NM_SETTINGS_PLUGIN (iter->data);

		g_signal_connect (plugin, NM_SETTINGS_PLUGIN_UNMANAGED_SPECS_CHANGED,
		                  G_CALLBACK (_plugin_unmanaged_specs_changed), self);
		g_signal_connect (plugin, NM_SETTINGS_PLUGIN_UNRECOGNIZED_SPECS_CHANGED,
		                  G_CALLBACK (_plugin_unrecognized_specs_changed), self);
	}

	_plugin_unmanaged_specs_changed (NULL, self);
	_plugin_unrecognized_specs_changed (NULL, self);

	for (iter = priv->plugins; iter; iter = iter->next) {
		nm_settings_plugin_reload_connections (iter->data,
		                                       _plugin_reload_connections_cb,
		                                       self);
	}

	_startup_complete_check (self);

	g_signal_connect (priv->hostname_manager,
	                  "notify::"NM_HOSTNAME_MANAGER_HOSTNAME,
	                  G_CALLBACK (_hostname_changed_cb),
	                  self);
	if (nm_hostname_manager_get_hostname (priv->hostname_manager))
		_notify (self, PROP_HOSTNAME);

	return TRUE;
}

/*****************************************************************************/

static void
get_property (GObject *object, guint prop_id,
              GValue *value, GParamSpec *pspec)
{
	NMSettings *self = NM_SETTINGS (object);
	NMSettingsPrivate *priv = NM_SETTINGS_GET_PRIVATE (self);
	const char **strv;

	switch (prop_id) {
	case PROP_UNMANAGED_SPECS:
		g_value_take_boxed (value,
		                    _nm_utils_slist_to_strv (nm_settings_get_unmanaged_specs (self),
		                                             TRUE));
		break;
	case PROP_HOSTNAME:
		g_value_set_string (value,
		                      priv->hostname_manager
		                    ? nm_hostname_manager_get_hostname (priv->hostname_manager)
		                    : NULL);
		break;
	case PROP_CAN_MODIFY:
		g_value_set_boolean (value, TRUE);
		break;
	case PROP_CONNECTIONS:
		strv = nm_dbus_utils_get_paths_for_clist (&priv->connections_lst_head,
		                                          priv->connections_len,
		                                          G_STRUCT_OFFSET (NMSettingsConnection, _connections_lst),
		                                          TRUE);
		g_value_take_boxed (value, nm_utils_strv_make_deep_copied (strv));
		break;
	case PROP_STARTUP_COMPLETE:
		g_value_set_boolean (value, !nm_settings_get_startup_complete_blocked_reason (self));
		break;
	default:
		G_OBJECT_WARN_INVALID_PROPERTY_ID (object, prop_id, pspec);
		break;
	}
}

/*****************************************************************************/

static void
nm_settings_init (NMSettings *self)
{
	NMSettingsPrivate *priv = NM_SETTINGS_GET_PRIVATE (self);

	c_list_init (&priv->auth_lst_head);
	c_list_init (&priv->connections_lst_head);

	priv->sett_conn_entries = g_hash_table_new_full (nm_pstr_hash, nm_pstr_equal,
	                                                 NULL, (GDestroyNotify) _sett_conn_entry_free);

	priv->config = g_object_ref (nm_config_get ());

	priv->agent_mgr = g_object_ref (nm_agent_manager_get ());

	priv->session_monitor = g_object_ref (nm_session_monitor_get ());
	g_signal_connect (priv->session_monitor,
	                  NM_SESSION_MONITOR_CHANGED,
	                  G_CALLBACK (session_monitor_changed_cb),
	                  self);
}

NMSettings *
nm_settings_new (void)
{
	return g_object_new (NM_TYPE_SETTINGS, NULL);
}

static void
dispose (GObject *object)
{
	NMSettings *self = NM_SETTINGS (object);
	NMSettingsPrivate *priv = NM_SETTINGS_GET_PRIVATE (self);
	CList *iter;

	g_clear_object (&priv->startup_complete_blocked_by);

	while ((iter = c_list_first (&priv->auth_lst_head)))
		nm_auth_chain_destroy (nm_auth_chain_parent_lst_entry (iter));

	if (priv->hostname_manager) {
		g_signal_handlers_disconnect_by_func (priv->hostname_manager,
		                                      G_CALLBACK (_hostname_changed_cb),
		                                      self);
		g_clear_object (&priv->hostname_manager);
	}

	if (priv->session_monitor) {
		g_signal_handlers_disconnect_by_func (priv->session_monitor,
		                                      G_CALLBACK (session_monitor_changed_cb),
		                                      self);
		g_clear_object (&priv->session_monitor);
	}

	G_OBJECT_CLASS (nm_settings_parent_class)->dispose (object);
}

static void
finalize (GObject *object)
{
	NMSettings *self = NM_SETTINGS (object);
	NMSettingsPrivate *priv = NM_SETTINGS_GET_PRIVATE (self);
	GSList *iter;

	_clear_connections_cached_list (priv);

	nm_assert (c_list_is_empty (&priv->connections_lst_head));

	g_slist_free_full (priv->unmanaged_specs, g_free);
	g_slist_free_full (priv->unrecognized_specs, g_free);

	while ((iter = priv->plugins)) {
		gs_unref_object NMSettingsPlugin *plugin = iter->data;

		priv->plugins = g_slist_delete_link (priv->plugins, iter);
		g_signal_handlers_disconnect_by_data (plugin, self);
	}

	g_clear_object (&priv->keyfile_plugin);

	g_clear_object (&priv->agent_mgr);

	g_clear_object (&priv->config);

	nm_clear_g_source (&priv->kf_db_flush_idle_id_timestamps);
	nm_clear_g_source (&priv->kf_db_flush_idle_id_seen_bssids);
	nm_key_file_db_to_file (priv->kf_db_timestamps, FALSE);
	nm_key_file_db_to_file (priv->kf_db_seen_bssids, FALSE);
	nm_key_file_db_destroy (priv->kf_db_timestamps);
	nm_key_file_db_destroy (priv->kf_db_seen_bssids);

	G_OBJECT_CLASS (nm_settings_parent_class)->finalize (object);
}

static const GDBusSignalInfo signal_info_new_connection = NM_DEFINE_GDBUS_SIGNAL_INFO_INIT (
	"NewConnection",
	.args = NM_DEFINE_GDBUS_ARG_INFOS (
		NM_DEFINE_GDBUS_ARG_INFO ("connection", "o"),
	),
);

static const GDBusSignalInfo signal_info_connection_removed = NM_DEFINE_GDBUS_SIGNAL_INFO_INIT (
	"ConnectionRemoved",
	.args = NM_DEFINE_GDBUS_ARG_INFOS (
		NM_DEFINE_GDBUS_ARG_INFO ("connection", "o"),
	),
);

static const NMDBusInterfaceInfoExtended interface_info_settings = {
	.parent = NM_DEFINE_GDBUS_INTERFACE_INFO_INIT (
		NM_DBUS_INTERFACE_SETTINGS,
		.methods = NM_DEFINE_GDBUS_METHOD_INFOS (
			NM_DEFINE_DBUS_METHOD_INFO_EXTENDED (
				NM_DEFINE_GDBUS_METHOD_INFO_INIT (
					"ListConnections",
					.out_args = NM_DEFINE_GDBUS_ARG_INFOS (
						NM_DEFINE_GDBUS_ARG_INFO ("connections", "ao"),
					),
				),
				.handle = impl_settings_list_connections,
			),
			NM_DEFINE_DBUS_METHOD_INFO_EXTENDED (
				NM_DEFINE_GDBUS_METHOD_INFO_INIT (
					"GetConnectionByUuid",
					.in_args = NM_DEFINE_GDBUS_ARG_INFOS (
						NM_DEFINE_GDBUS_ARG_INFO ("uuid", "s"),
					),
					.out_args = NM_DEFINE_GDBUS_ARG_INFOS (
						NM_DEFINE_GDBUS_ARG_INFO ("connection", "o"),
					),
				),
				.handle = impl_settings_get_connection_by_uuid,
			),
			NM_DEFINE_DBUS_METHOD_INFO_EXTENDED (
				NM_DEFINE_GDBUS_METHOD_INFO_INIT (
					"AddConnection",
					.in_args = NM_DEFINE_GDBUS_ARG_INFOS (
						NM_DEFINE_GDBUS_ARG_INFO ("connection", "a{sa{sv}}"),
					),
					.out_args = NM_DEFINE_GDBUS_ARG_INFOS (
						NM_DEFINE_GDBUS_ARG_INFO ("path", "o"),
					),
				),
				.handle = impl_settings_add_connection,
			),
			NM_DEFINE_DBUS_METHOD_INFO_EXTENDED (
				NM_DEFINE_GDBUS_METHOD_INFO_INIT (
					"AddConnectionUnsaved",
					.in_args = NM_DEFINE_GDBUS_ARG_INFOS (
						NM_DEFINE_GDBUS_ARG_INFO ("connection", "a{sa{sv}}"),
					),
					.out_args = NM_DEFINE_GDBUS_ARG_INFOS (
						NM_DEFINE_GDBUS_ARG_INFO ("path", "o"),
					),
				),
				.handle = impl_settings_add_connection_unsaved,
			),
			NM_DEFINE_DBUS_METHOD_INFO_EXTENDED (
				NM_DEFINE_GDBUS_METHOD_INFO_INIT (
					"LoadConnections",
					.in_args = NM_DEFINE_GDBUS_ARG_INFOS (
						NM_DEFINE_GDBUS_ARG_INFO ("filenames", "as"),
					),
					.out_args = NM_DEFINE_GDBUS_ARG_INFOS (
						NM_DEFINE_GDBUS_ARG_INFO ("status", "b"),
						NM_DEFINE_GDBUS_ARG_INFO ("failures", "as"),
					),
				),
				.handle = impl_settings_load_connections,
			),
			NM_DEFINE_DBUS_METHOD_INFO_EXTENDED (
				NM_DEFINE_GDBUS_METHOD_INFO_INIT (
					"ReloadConnections",
					.out_args = NM_DEFINE_GDBUS_ARG_INFOS (
						NM_DEFINE_GDBUS_ARG_INFO ("status", "b"),
					),
				),
				.handle = impl_settings_reload_connections,
			),
			NM_DEFINE_DBUS_METHOD_INFO_EXTENDED (
				NM_DEFINE_GDBUS_METHOD_INFO_INIT (
					"SaveHostname",
					.in_args = NM_DEFINE_GDBUS_ARG_INFOS (
						NM_DEFINE_GDBUS_ARG_INFO ("hostname", "s"),
					),
				),
				.handle = impl_settings_save_hostname,
			),
		),
		.signals = NM_DEFINE_GDBUS_SIGNAL_INFOS (
			&nm_signal_info_property_changed_legacy,
			&signal_info_new_connection,
			&signal_info_connection_removed,
		),
		.properties = NM_DEFINE_GDBUS_PROPERTY_INFOS (
			NM_DEFINE_DBUS_PROPERTY_INFO_EXTENDED_READABLE_L ("Connections", "ao", NM_SETTINGS_CONNECTIONS),
			NM_DEFINE_DBUS_PROPERTY_INFO_EXTENDED_READABLE_L ("Hostname",    "s",  NM_SETTINGS_HOSTNAME),
			NM_DEFINE_DBUS_PROPERTY_INFO_EXTENDED_READABLE_L ("CanModify",   "b",  NM_SETTINGS_CAN_MODIFY),
		),
	),
	.legacy_property_changed = TRUE,
};

static void
nm_settings_class_init (NMSettingsClass *class)
{
	GObjectClass *object_class = G_OBJECT_CLASS (class);
	NMDBusObjectClass *dbus_object_class = NM_DBUS_OBJECT_CLASS (class);

	dbus_object_class->export_path = NM_DBUS_EXPORT_PATH_STATIC (NM_DBUS_PATH_SETTINGS);
	dbus_object_class->interface_infos = NM_DBUS_INTERFACE_INFOS (&interface_info_settings);

	object_class->get_property = get_property;
	object_class->dispose = dispose;
	object_class->finalize = finalize;

	obj_properties[PROP_UNMANAGED_SPECS] =
	    g_param_spec_boxed (NM_SETTINGS_UNMANAGED_SPECS, "", "",
	                        G_TYPE_STRV,
	                        G_PARAM_READABLE |
	                        G_PARAM_STATIC_STRINGS);

	obj_properties[PROP_HOSTNAME] =
	    g_param_spec_string (NM_SETTINGS_HOSTNAME, "", "",
	                         NULL,
	                         G_PARAM_READABLE |
	                         G_PARAM_STATIC_STRINGS);

	obj_properties[PROP_CAN_MODIFY] =
	    g_param_spec_boolean (NM_SETTINGS_CAN_MODIFY, "", "",
	                          FALSE,
	                          G_PARAM_READABLE |
	                          G_PARAM_STATIC_STRINGS);

	obj_properties[PROP_CONNECTIONS] =
	    g_param_spec_boxed (NM_SETTINGS_CONNECTIONS, "", "",
	                        G_TYPE_STRV,
	                        G_PARAM_READABLE |
	                        G_PARAM_STATIC_STRINGS);

	obj_properties[PROP_STARTUP_COMPLETE] =
	    g_param_spec_boolean (NM_SETTINGS_STARTUP_COMPLETE, "", "",
	                          FALSE,
	                          G_PARAM_READABLE |
	                          G_PARAM_STATIC_STRINGS);

	g_object_class_install_properties (object_class, _PROPERTY_ENUMS_LAST, obj_properties);

	signals[CONNECTION_ADDED] =
	    g_signal_new (NM_SETTINGS_SIGNAL_CONNECTION_ADDED,
	                  G_OBJECT_CLASS_TYPE (object_class),
	                  G_SIGNAL_RUN_FIRST,
	                  0, NULL, NULL,
	                  g_cclosure_marshal_VOID__OBJECT,
	                  G_TYPE_NONE, 1, NM_TYPE_SETTINGS_CONNECTION);

	signals[CONNECTION_UPDATED] =
	    g_signal_new (NM_SETTINGS_SIGNAL_CONNECTION_UPDATED,
	                  G_OBJECT_CLASS_TYPE (object_class),
	                  G_SIGNAL_RUN_FIRST,
	                  0, NULL, NULL,
	                  NULL,
	                  G_TYPE_NONE, 2, NM_TYPE_SETTINGS_CONNECTION, G_TYPE_BOOLEAN);

	signals[CONNECTION_REMOVED] =
	    g_signal_new (NM_SETTINGS_SIGNAL_CONNECTION_REMOVED,
	                  G_OBJECT_CLASS_TYPE (object_class),
	                  G_SIGNAL_RUN_FIRST,
	                  0, NULL, NULL,
	                  g_cclosure_marshal_VOID__OBJECT,
	                  G_TYPE_NONE, 1, NM_TYPE_SETTINGS_CONNECTION);

	signals[CONNECTION_FLAGS_CHANGED] =
	    g_signal_new (NM_SETTINGS_SIGNAL_CONNECTION_FLAGS_CHANGED,
	                  G_OBJECT_CLASS_TYPE (object_class),
	                  G_SIGNAL_RUN_FIRST,
	                  0, NULL, NULL,
	                  g_cclosure_marshal_VOID__OBJECT,
	                  G_TYPE_NONE, 1, NM_TYPE_SETTINGS_CONNECTION);
}
