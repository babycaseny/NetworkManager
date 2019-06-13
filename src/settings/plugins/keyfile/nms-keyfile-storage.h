/* NetworkManager system settings service - keyfile plugin
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
 * Copyright (C) 2018 Red Hat, Inc.
 */

#ifndef __NMS_KEYFILE_STORAGE_H__
#define __NMS_KEYFILE_STORAGE_H__

#include "c-list/src/c-list.h"
#include "settings/nm-settings-storage.h"
#include "nms-keyfile-utils.h"

/*****************************************************************************/

#define NMS_TYPE_KEYFILE_STORAGE            (nms_keyfile_storage_get_type ())
#define NMS_KEYFILE_STORAGE(obj)            (G_TYPE_CHECK_INSTANCE_CAST ((obj), NMS_TYPE_KEYFILE_STORAGE, NMSKeyfileStorage))
#define NMS_KEYFILE_STORAGE_CLASS(klass)    (G_TYPE_CHECK_CLASS_CAST ((klass), NMS_TYPE_KEYFILE_STORAGE, NMSKeyfileStorageClass))
#define NMS_IS_KEYFILE_STORAGE(obj)         (G_TYPE_CHECK_INSTANCE_TYPE ((obj), NMS_TYPE_KEYFILE_STORAGE))
#define NMS_IS_KEYFILE_STORAGE_CLASS(klass) (G_TYPE_CHECK_CLASS_TYPE ((klass), NMS_TYPE_KEYFILE_STORAGE))
#define NMS_KEYFILE_STORAGE_GET_CLASS(obj)  (G_TYPE_INSTANCE_GET_CLASS ((obj), NMS_TYPE_KEYFILE_STORAGE, NMSKeyfileStorageClass))

typedef struct {
	NMSettingsStorage parent;

	CList storage_lst;

	CList filename_idx_lst;

	/* Keep a reference of the exported connection. We only need this during
	 * reload and load, to check whether the content on disk changed. */
	NMConnection *connection_exported;

	/* Only relevant during reload-all. It contains a list of all the files
	 * that are associated with this UUID. In general, any number of
	 * files can have connection profiles for a particular UUID. During
	 * _do_reload_all(), we need to load all of them and find the best one.
	 *
	 * This is to simplify reload, because we can figure out whether a UUID
	 * was added, unchanged, or removed by reusing the list of tracked storages.
	 *
	 * After reload-all, this list is cleared again. */
	struct _NMSKeyfileConnReloadHead *_reload_data_head;

	NMSKeyfileStorageType storage_type_exported;

	bool is_in_memory:1;
} NMSKeyfileStorage;

typedef struct _NMSKeyfileStorageClass NMSKeyfileStorageClass;

GType nms_keyfile_storage_get_type (void);

struct _NMSKeyfilePlugin;

NMSKeyfileStorage *nms_keyfile_storage_new (struct _NMSKeyfilePlugin *plugin,
                                            const char *uuid);

void _nms_keyfile_storage_clear (NMSKeyfileStorage *storage);

/*****************************************************************************/

static inline const char *
nms_keyfile_storage_get_uuid (NMSKeyfileStorage *self)
{
	nm_assert (NMS_IS_KEYFILE_STORAGE (self));

	return nm_settings_storage_get_uuid (NM_SETTINGS_STORAGE (self));
}

static inline const char *
nms_keyfile_storage_get_filename (NMSKeyfileStorage *self)
{
	nm_assert (NMS_IS_KEYFILE_STORAGE (self));

	return nm_settings_storage_get_filename (NM_SETTINGS_STORAGE (self));
}

/*****************************************************************************/

static inline gboolean
nm_settings_storage_is_keyfile (NMSettingsStorage *self,
                                gboolean *out_is_in_memory)
{
	if (NMS_IS_KEYFILE_STORAGE (self)) {
		NM_SET_OUT (out_is_in_memory, (((NMSKeyfileStorage *) self)->storage_type_exported == NMS_KEYFILE_STORAGE_TYPE_RUN));
		return TRUE;
	}
	NM_SET_OUT (out_is_in_memory, FALSE);
	return FALSE;
}

static inline gboolean
nm_settings_storage_is_in_memory (NMSettingsStorage *self)
{
	return    NMS_IS_KEYFILE_STORAGE (self)
	       && (((NMSKeyfileStorage *) self)->storage_type_exported == NMS_KEYFILE_STORAGE_TYPE_RUN);
}

#endif /* __NMS_KEYFILE_STORAGE_H__ */
