/*
 * This library is free software; you can redistribute it and/or
 * modify it under the terms of the GNU Lesser General Public
 * License as published by the Free Software Foundation; either
 * version 2 of the License, or (at your option) any later version.
 *
 * This library is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 * Lesser General Public License for more details.
 *
 * You should have received a copy of the GNU Lesser General Public
 * License along with this library; if not, write to the
 * Free Software Foundation, Inc., 51 Franklin Street, Fifth Floor,
 * Boston, MA 02110-1301 USA.
 *
 * (C) Copyright 2019 Red Hat, Inc.
 */

#include "nm-default.h"

#include "nm-dhcp-options.h"

const char *
request_string (const ReqOption *requests, guint option)
{
	guint i = 0;

	while (requests[i].name) {
		if (requests[i].option_num == option)
			return requests[i].name + NM_STRLEN (REQPREFIX);
		i++;
	}

	/* Option should always be found */
	nm_assert_not_reached ();
	return NULL;
}

void
take_option (GHashTable *options,
             const ReqOption *requests,
             guint option,
             char *value)
{
	nm_assert (options);
	nm_assert (requests);
	nm_assert (value);

	g_hash_table_insert (options,
	                     (gpointer) request_string (requests, option),
	                     value);
}

void
add_option (GHashTable *options, const ReqOption *requests, guint option, const char *value)
{
	if (options)
		take_option (options, requests, option, g_strdup (value));
}

void
add_option_u64 (GHashTable *options, const ReqOption *requests, guint option, guint64 value)
{
	if (options)
		take_option (options, requests, option, g_strdup_printf ("%" G_GUINT64_FORMAT, value));
}

void
add_requests_to_options (GHashTable *options, const ReqOption *requests)
{
	guint i;

	if (!options)
		return;

	for (i = 0; requests[i].name; i++) {
		if (requests[i].include)
			g_hash_table_insert (options, (gpointer) requests[i].name, g_strdup ("1"));
	}
}

GHashTable *
create_options_dict (void)
{
	return g_hash_table_new_full (nm_str_hash, g_str_equal, NULL, g_free);
}

