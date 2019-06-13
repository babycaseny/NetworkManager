/* NetworkManager system settings service
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
 * Copyright (C) 2007 - 2018 Red Hat, Inc.
 * Copyright (C) 2008 Novell, Inc.
 */

#ifndef __NM_SETTINGS_PLUGIN_H__
#define __NM_SETTINGS_PLUGIN_H__

#include "nm-connection.h"

#include "nm-settings-storage.h"

typedef struct _NMSettingsPlugin NMSettingsPlugin;

typedef void (*NMSettingsPluginConnectionReloadCallback) (NMSettingsPlugin *self,
                                                          NMSettingsStorage *storage,
                                                          NMConnection *connection,
                                                          gpointer user_data);

#define NM_TYPE_SETTINGS_PLUGIN               (nm_settings_plugin_get_type ())
#define NM_SETTINGS_PLUGIN(obj)               (G_TYPE_CHECK_INSTANCE_CAST ((obj), NM_TYPE_SETTINGS_PLUGIN, NMSettingsPlugin))
#define NM_SETTINGS_PLUGIN_CLASS(klass)       (G_TYPE_CHECK_CLASS_CAST ((klass), NM_TYPE_SETTINGS_PLUGIN, NMSettingsPluginClass))
#define NM_IS_SETTINGS_PLUGIN(obj)            (G_TYPE_CHECK_INSTANCE_TYPE ((obj), NM_TYPE_SETTINGS_PLUGIN))
#define NM_IS_SETTINGS_PLUGIN_CLASS(klass)    (G_TYPE_CHECK_CLASS_TYPE ((klass), NM_TYPE_SETTINGS_PLUGIN))
#define NM_SETTINGS_PLUGIN_GET_CLASS(obj)     (G_TYPE_INSTANCE_GET_CLASS ((obj), NM_TYPE_SETTINGS_PLUGIN, NMSettingsPluginClass))

#define NM_SETTINGS_PLUGIN_UNMANAGED_SPECS_CHANGED    "unmanaged-specs-changed"
#define NM_SETTINGS_PLUGIN_UNRECOGNIZED_SPECS_CHANGED "unrecognized-specs-changed"

struct _NMSettingsPlugin {
	GObject parent;
};

typedef struct {
	GObjectClass parent;

	/*
	 * Return a string list of specifications of devices which NetworkManager
	 * should not manage.  Returned list will be freed by the system settings
	 * service, and each element must be allocated using g_malloc() or its
	 * variants (g_strdup, g_strdup_printf, etc).
	 *
	 * Each string in the list must be in one of the formats recognized by
	 * nm_device_spec_match_list().
	 */
	GSList * (*get_unmanaged_specs) (NMSettingsPlugin *self);

	/*
	 * Return a string list of specifications of devices for which at least
	 * one non-NetworkManager-based configuration is defined. Returned list
	 * will be freed by the system settings service, and each element must be
	 * allocated using g_malloc() or its variants (g_strdup, g_strdup_printf,
	 * etc).
	 *
	 * Each string in the list must be in one of the formats recognized by
	 * nm_device_spec_match_list().
	 */
	GSList * (*get_unrecognized_specs) (NMSettingsPlugin *self);

	/* Requests that the plugin load/reload a single connection, if it
	 * recognizes the filename. Returns success or failure.
	 */
	gboolean (*load_connection) (NMSettingsPlugin *self,
	                             const char *filename,
	                             NMSettingsStorage **out_storage,
	                             NMConnection **out_connection,
	                             GPtrArray **out_replaced_storages,
	                             GError **error);

	/* Requests that the plugin reload all connection files from disk,
	 * and emit signals reflecting new, changed, and removed connections.
	 */
	void (*reload_connections) (NMSettingsPlugin *self,
	                            NMSettingsPluginConnectionReloadCallback callback,
	                            gpointer user_data);

	gboolean (*add_connection) (NMSettingsPlugin *self,
	                            NMConnection *connection,
	                            NMSettingsStorage **out_storage,
	                            NMConnection **out_connection,
	                            GError **error);

	gboolean (*update_connection) (NMSettingsPlugin *self,
	                               NMSettingsStorage *storage,
	                               NMConnection *connection,
	                               NMSettingsStorage **out_storage,
	                               NMConnection **out_connection,
	                               GError **error);

	gboolean (*delete_connection) (NMSettingsPlugin *self,
	                               NMSettingsStorage *storage,
	                               gboolean remove_from_disk,
	                               GError **error);

} NMSettingsPluginClass;

/*****************************************************************************/

GType nm_settings_plugin_get_type (void);

/*****************************************************************************/

GSList *nm_settings_plugin_get_unmanaged_specs (NMSettingsPlugin *self);
GSList *nm_settings_plugin_get_unrecognized_specs (NMSettingsPlugin *self);

void nm_settings_plugin_reload_connections (NMSettingsPlugin *self,
                                            NMSettingsPluginConnectionReloadCallback callback,
                                            gpointer user_data);

gboolean nm_settings_plugin_load_connection (NMSettingsPlugin *self,
                                             const char *filename,
                                             NMSettingsStorage **out_storage,
                                             NMConnection **out_connection,
                                             GPtrArray **out_replaced_storages,
                                             GError **error);

gboolean nm_settings_plugin_add_connection (NMSettingsPlugin *self,
                                            NMConnection *connection,
                                            NMSettingsStorage **out_storage,
                                            NMConnection **out_connection,
                                            GError **error);

gboolean nm_settings_plugin_update_connection (NMSettingsPlugin *self,
                                               NMSettingsStorage *storage,
                                               NMConnection *connection,
                                               NMSettingsStorage **out_storage,
                                               NMConnection **out_connection,
                                               GError **error);

gboolean nm_settings_plugin_delete_connection (NMSettingsPlugin *self,
                                               NMSettingsStorage *storage,
                                               gboolean remove_from_disk,
                                               GError **error);

/*****************************************************************************/

typedef NMSettingsPlugin *(*NMSettingsPluginFactoryFunc) (void);

NMSettingsPlugin *nm_settings_plugin_factory (void);

/*****************************************************************************
 * Internal API
 *****************************************************************************/

void _nm_settings_plugin_emit_signal_unmanaged_specs_changed (NMSettingsPlugin *self);

void _nm_settings_plugin_emit_signal_unrecognized_specs_changed (NMSettingsPlugin *self);

#endif /* __NM_SETTINGS_PLUGIN_H__ */
